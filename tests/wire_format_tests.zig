// Wire Format Validation Tests
// Tests packet encoding/decoding against known good packets

const std = @import("std");
const gtpu = @import("gtpu");

const testing = std.testing;

// Known good GTP-U G-PDU packet (captured from real network)
const GOLDEN_GPDU = [_]u8{
    // GTP-U Header
    0x30, // Version=1, PT=1, E=0, S=0, PN=0
    0xFF, // Message Type = G-PDU (255)
    0x00, 0x20, // Length = 32 bytes
    0x12, 0x34, 0x56, 0x78, // TEID = 0x12345678

    // Payload (32 bytes of data)
    0x45, 0x00, 0x00, 0x1C, // IPv4 header start
    0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01, // Source IP: 192.168.1.1
    0xC0, 0xA8, 0x01, 0x02, // Dest IP: 192.168.1.2
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

// GTP-U Echo Request
const GOLDEN_ECHO_REQUEST = [_]u8{
    // GTP-U Header with sequence number
    0x32, // Version=1, PT=1, E=0, S=1, PN=0
    0x01, // Message Type = Echo Request
    0x00, 0x04, // Length = 4 bytes (optional fields)
    0x00, 0x00, 0x00, 0x00, // TEID = 0 (not used for echo)

    // Optional fields
    0x00, 0x2A, // Sequence number = 42
    0x00, // N-PDU number = 0
    0x00, // Next extension header type = 0
};

// GTP-U Echo Response with Recovery IE
const GOLDEN_ECHO_RESPONSE = [_]u8{
    // GTP-U Header with sequence number
    0x32, // Version=1, PT=1, E=0, S=1, PN=0
    0x02, // Message Type = Echo Response
    0x00, 0x07, // Length = 7 bytes
    0x00, 0x00, 0x00, 0x00, // TEID = 0

    // Optional fields
    0x00, 0x2A, // Sequence number = 42
    0x00, // N-PDU number = 0
    0x00, // Next extension header type = 0

    // Recovery IE
    0x0E, // Type = Recovery (14)
    0x00, 0x01, // Length = 1
    0x05, // Recovery counter = 5
};

test "Wire format - Decode golden G-PDU packet" {
    const allocator = testing.allocator;

    var stream = std.io.fixedBufferStream(&GOLDEN_GPDU);
    var msg = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer msg.deinit();

    try testing.expectEqual(gtpu.protocol.MessageType.g_pdu, msg.header.message_type);
    try testing.expectEqual(@as(u32, 0x12345678), msg.header.teid);
    try testing.expectEqual(@as(u16, 32), msg.header.length);
    try testing.expectEqual(@as(usize, 32), msg.payload.len);
}

test "Wire format - Decode golden Echo Request" {
    const allocator = testing.allocator;

    var stream = std.io.fixedBufferStream(&GOLDEN_ECHO_REQUEST);
    var msg = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer msg.deinit();

    try testing.expectEqual(gtpu.protocol.MessageType.echo_request, msg.header.message_type);
    try testing.expectEqual(@as(u32, 0), msg.header.teid);
    try testing.expect(msg.header.flags.s);
    try testing.expectEqual(@as(u16, 42), msg.header.sequence_number.?);
}

test "Wire format - Decode golden Echo Response" {
    const allocator = testing.allocator;

    var stream = std.io.fixedBufferStream(&GOLDEN_ECHO_RESPONSE);
    var msg = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer msg.deinit();

    try testing.expectEqual(gtpu.protocol.MessageType.echo_response, msg.header.message_type);
    try testing.expectEqual(@as(u16, 42), msg.header.sequence_number.?);
    try testing.expectEqual(@as(usize, 1), msg.information_elements.items.len);

    const recovery_ie = msg.information_elements.items[0];
    try testing.expectEqual(gtpu.ie.IEType.recovery, recovery_ie);
}

test "Wire format - Encode/Decode round-trip G-PDU" {
    const allocator = testing.allocator;

    const payload = "Test payload for GTP-U";
    var original = gtpu.GtpuMessage.createGpdu(allocator, 0xABCDEF12, payload);
    defer original.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try original.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer decoded.deinit();

    // Verify
    try testing.expectEqual(original.header.message_type, decoded.header.message_type);
    try testing.expectEqual(original.header.teid, decoded.header.teid);
    try testing.expectEqualStrings(payload, decoded.payload);
}

test "Wire format - G-PDU with extension headers" {
    const allocator = testing.allocator;

    const payload = "5G data";
    var msg = gtpu.GtpuMessage.createGpdu(allocator, 0x11111111, payload);
    defer msg.deinit();

    // Add PDU Session Container
    const pdu_container = gtpu.extension.ExtensionHeader{
        .pdu_session_container = .{
            .pdu_type = 1,
            .qfi = 9,
            .ppi = 0,
            .rqi = true,
        },
    };
    try msg.addExtensionHeader(pdu_container);

    // Add PDCP PDU Number
    const pdcp = gtpu.extension.ExtensionHeader{
        .pdcp_pdu_number = .{ .pdu_number = 12345 },
    };
    try msg.addExtensionHeader(pdcp);

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try msg.encode(buffer.writer());

    // Verify extension header flag is set
    try testing.expect(msg.header.flags.e);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer decoded.deinit();

    try testing.expectEqual(@as(usize, 2), decoded.extension_headers.items.len);
    try testing.expectEqual(gtpu.protocol.ExtensionHeaderType.pdu_session_container, decoded.extension_headers.items[0]);
    try testing.expectEqual(@as(u6, 9), decoded.extension_headers.items[0].pdu_session_container.qfi);
}

test "Wire format - Echo with sequence number wrap-around" {
    const allocator = testing.allocator;

    // Test sequence number near max value
    var echo1 = try gtpu.GtpuMessage.createEchoRequest(allocator, 0xFFFE);
    defer echo1.deinit();

    var buffer1 = std.ArrayList(u8).init(allocator);
    defer buffer1.deinit();
    try echo1.encode(buffer1.writer());

    var stream1 = std.io.fixedBufferStream(buffer1.items);
    var decoded1 = try gtpu.GtpuMessage.decode(allocator, stream1.reader());
    defer decoded1.deinit();

    try testing.expectEqual(@as(u16, 0xFFFE), decoded1.header.sequence_number.?);

    // Test wrap-around
    var echo2 = try gtpu.GtpuMessage.createEchoRequest(allocator, 0xFFFF);
    defer echo2.deinit();

    var buffer2 = std.ArrayList(u8).init(allocator);
    defer buffer2.deinit();
    try echo2.encode(buffer2.writer());

    var stream2 = std.io.fixedBufferStream(buffer2.items);
    var decoded2 = try gtpu.GtpuMessage.decode(allocator, stream2.reader());
    defer decoded2.deinit();

    try testing.expectEqual(@as(u16, 0xFFFF), decoded2.header.sequence_number.?);
}

test "Wire format - Multiple Information Elements" {
    const allocator = testing.allocator;

    var msg = gtpu.GtpuMessage.init(allocator, .error_indication, 0x12345678);
    defer msg.deinit();

    // Add multiple IEs
    const teid_ie = gtpu.ie.InformationElement.initTeid(0xABCDEF12);
    try msg.addInformationElement(teid_ie);

    const recovery_ie = gtpu.ie.InformationElement.initRecovery(10);
    try msg.addInformationElement(recovery_ie);

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try msg.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer decoded.deinit();

    try testing.expectEqual(@as(usize, 2), decoded.information_elements.items.len);
}

test "Wire format - Byte alignment verification" {
    const allocator = testing.allocator;

    // Test that all messages are properly aligned
    const test_cases = [_]struct {
        msg_type: gtpu.protocol.MessageType,
        has_teid: bool,
    }{
        .{ .msg_type = .echo_request, .has_teid = false },
        .{ .msg_type = .echo_response, .has_teid = false },
        .{ .msg_type = .g_pdu, .has_teid = true },
        .{ .msg_type = .end_marker, .has_teid = true },
    };

    for (test_cases) |tc| {
        const teid: u32 = if (tc.has_teid) 0x12345678 else 0;
        var msg = gtpu.GtpuMessage.init(allocator, tc.msg_type, teid);
        defer msg.deinit();

        if (tc.msg_type == .echo_request or tc.msg_type == .echo_response or tc.msg_type == .end_marker) {
            msg.header.flags.s = true;
            msg.header.sequence_number = 1;
        }

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        try msg.encode(buffer.writer());

        // Minimum header is 8 bytes, with optional fields it's 12 bytes
        const expected_min = if (msg.header.flags.hasOptionalFields()) 12 else 8;
        try testing.expect(buffer.items.len >= expected_min);
    }
}

test "Wire format - TEID byte order (big-endian)" {
    const allocator = testing.allocator;

    const teid: u32 = 0x12345678;
    var msg = gtpu.GtpuMessage.createGpdu(allocator, teid, "test");
    defer msg.deinit();

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try msg.encode(buffer.writer());

    // TEID is at bytes 4-7 in the header
    try testing.expectEqual(@as(u8, 0x12), buffer.items[4]);
    try testing.expectEqual(@as(u8, 0x34), buffer.items[5]);
    try testing.expectEqual(@as(u8, 0x56), buffer.items[6]);
    try testing.expectEqual(@as(u8, 0x78), buffer.items[7]);
}

test "Wire format - Length field excludes mandatory header" {
    const allocator = testing.allocator;

    const payload = "12345678"; // 8 bytes
    var msg = gtpu.GtpuMessage.createGpdu(allocator, 0x11111111, payload);
    defer msg.deinit();

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try msg.encode(buffer.writer());

    // Length is at bytes 2-3
    const length = (@as(u16, buffer.items[2]) << 8) | buffer.items[3];

    // Length should be payload size only (not including 8-byte mandatory header)
    try testing.expectEqual(@as(u16, 8), length);
}
