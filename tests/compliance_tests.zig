// 3GPP Compliance Tests
// Tests for 3GPP TS 29.281 compliance

const std = @import("std");
const gtpu = @import("../src/lib.zig");

const testing = std.testing;

// Test 1: GTP-U Header Format (3GPP TS 29.281 Section 5.1)
test "3GPP TS 29.281 - Header format compliance" {
    const allocator = testing.allocator;

    var header = gtpu.header.GtpuHeader.init(.g_pdu, 0x12345678);
    header.length = 100;

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try header.encode(buffer.writer());

    // Verify mandatory header size
    try testing.expectEqual(@as(usize, 8), buffer.items.len);

    // Verify version field
    try testing.expectEqual(gtpu.protocol.GTPU_VERSION, header.flags.version);

    // Verify protocol type
    try testing.expectEqual(@as(u1, 1), header.flags.pt);
}

// Test 2: Message Types (3GPP TS 29.281 Section 7.1)
test "3GPP TS 29.281 - Valid message types" {
    const valid_types = [_]gtpu.protocol.MessageType{
        .echo_request,
        .echo_response,
        .error_indication,
        .supported_extension_headers_notification,
        .g_pdu,
        .end_marker,
    };

    for (valid_types) |msg_type| {
        try testing.expect(msg_type.isValid());
    }
}

// Test 3: TEID Requirements (3GPP TS 29.281 Section 5.1)
test "3GPP TS 29.281 - TEID requirements" {
    // Echo messages should not require TEID
    try testing.expect(!gtpu.protocol.MessageType.echo_request.requiresTeid());
    try testing.expect(!gtpu.protocol.MessageType.echo_response.requiresTeid());

    // G-PDU requires TEID
    try testing.expect(gtpu.protocol.MessageType.g_pdu.requiresTeid());

    // End Marker requires TEID
    try testing.expect(gtpu.protocol.MessageType.end_marker.requiresTeid());
}

// Test 4: Extension Header Format (3GPP TS 29.281 Section 5.2)
test "3GPP TS 29.281 - Extension header format" {
    const allocator = testing.allocator;

    var ext: gtpu.extension.ExtensionHeader = .{
        .pdcp_pdu_number = .{ .pdu_number = 12345 },
    };
    defer ext.deinit();

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try ext.encode(buffer.writer(), true);

    // Extension header must be multiple of 4 bytes
    try testing.expect(buffer.items.len % 4 == 0);

    // First byte is length in 4-byte units
    const length_units = buffer.items[0];
    try testing.expectEqual(buffer.items.len, @as(usize, length_units) * 4);
}

// Test 5: PDU Session Container for 5G (3GPP TS 29.281 Section 5.2.3)
test "3GPP TS 29.281 - PDU Session Container" {
    const allocator = testing.allocator;

    const psc = gtpu.extension.PduSessionContainer{
        .pdu_type = 1, // UL
        .qfi = 9,
        .ppi = 0,
        .rqi = false,
    };

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try psc.encode(buffer.writer());

    // PDU Session Container is 2 bytes
    try testing.expectEqual(@as(usize, 2), buffer.items.len);

    // Decode and verify
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try gtpu.extension.PduSessionContainer.decode(stream.reader());

    try testing.expectEqual(psc.pdu_type, decoded.pdu_type);
    try testing.expectEqual(psc.qfi, decoded.qfi);
}

// Test 6: Echo Request/Response (3GPP TS 29.281 Section 4.4.1)
test "3GPP TS 29.281 - Echo mechanism" {
    const allocator = testing.allocator;

    // Echo Request must have sequence number
    var echo_req = try gtpu.GtpuMessage.createEchoRequest(allocator, 42);
    defer echo_req.deinit();

    try testing.expect(echo_req.header.flags.s);
    try testing.expectEqual(@as(u16, 42), echo_req.header.sequence_number.?);

    // Echo Response must contain Recovery IE
    var echo_resp = try gtpu.GtpuMessage.createEchoResponse(allocator, 42);
    defer echo_resp.deinit();

    try testing.expect(echo_resp.information_elements.items.len > 0);
    try testing.expectEqual(gtpu.ie.IEType.recovery, echo_resp.information_elements.items[0]);
}

// Test 7: Path Failure Detection (3GPP TS 29.281 Section 4.4)
test "3GPP TS 29.281 - Path failure detection" {
    const allocator = testing.allocator;

    const config = gtpu.path.PathConfig{
        .echo_interval_ms = 1000,
        .echo_timeout_ms = 500,
        .max_echo_failures = 3,
    };

    var path = gtpu.path.Path.init(try std.net.Address.parseIp("192.168.1.1", 2152), config);

    // Path should transition to failed after max_echo_failures
    const now = std.time.nanoTimestamp();

    _ = path.sendEcho(now);
    path.checkTimeout(now + 600 * std.time.ns_per_ms); // Timeout
    try testing.expectEqual(@as(u32, 1), path.consecutive_failures);

    _ = path.sendEcho(now + 700 * std.time.ns_per_ms);
    path.checkTimeout(now + 1300 * std.time.ns_per_ms); // Timeout
    try testing.expectEqual(@as(u32, 2), path.consecutive_failures);

    _ = path.sendEcho(now + 1400 * std.time.ns_per_ms);
    path.checkTimeout(now + 2000 * std.time.ns_per_ms); // Timeout
    try testing.expectEqual(@as(u32, 3), path.consecutive_failures);

    try testing.expectEqual(gtpu.path.PathState.failed, path.state);
}

// Test 8: QoS Flow Identifier (QFI) - 3GPP TS 23.501
test "3GPP TS 23.501 - QFI validation" {
    // QFI must be in range 0-63
    const valid_qfi: gtpu.qos.QFI = 9;
    try testing.expect(valid_qfi <= 63);

    // Test QoS flow creation with valid QFI
    const params = gtpu.qos.QosFlowParams{
        .qfi = valid_qfi,
        .fiveqi = .default_bearer,
        .arp = gtpu.qos.AllocationRetentionPriority.init(5),
    };

    try params.validate();
}

// Test 9: 5QI Characteristics (3GPP TS 23.501 Table 5.7.4-1)
test "3GPP TS 23.501 - 5QI characteristics" {
    // GBR flows
    try testing.expect(gtpu.qos.QosCharacteristics.conversational_voice.isGbr());
    try testing.expect(gtpu.qos.QosCharacteristics.conversational_video.isGbr());

    // Non-GBR flows
    try testing.expect(!gtpu.qos.QosCharacteristics.tcp_based.isGbr());

    // Delay-critical flows
    try testing.expect(gtpu.qos.QosCharacteristics.conversational_voice.isDelayReliant());
    try testing.expect(!gtpu.qos.QosCharacteristics.tcp_based.isDelayReliant());
}

// Test 10: Sequence Number Handling
test "3GPP TS 29.281 - Sequence number handling" {
    const allocator = testing.allocator;

    const config = gtpu.tunnel.TunnelConfig{
        .local_teid = 0x1234,
        .remote_teid = 0x5678,
        .local_address = try std.net.Address.parseIp("192.168.1.1", 2152),
        .remote_address = try std.net.Address.parseIp("192.168.1.2", 2152),
    };

    var tunnel = try gtpu.tunnel.Tunnel.init(allocator, config);
    defer tunnel.deinit();

    // First packet should be accepted
    try testing.expect(tunnel.checkSequence(100));

    // Duplicate should be rejected
    try testing.expect(!tunnel.checkSequence(100));

    // Newer packet should be accepted
    try testing.expect(tunnel.checkSequence(101));

    // Old packet should be rejected
    try testing.expect(!tunnel.checkSequence(50));
}

// Test 11: Mandatory IEs
test "3GPP TS 29.281 - Mandatory Information Elements" {
    const allocator = testing.allocator;

    // Recovery IE
    const recovery = gtpu.ie.InformationElement.initRecovery(0);
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try recovery.encode(buffer.writer());

    // IE format: Type (1) + Length (2) + Value
    try testing.expect(buffer.items.len >= 3);

    // Verify type
    try testing.expectEqual(@as(u8, @intFromEnum(gtpu.ie.IEType.recovery)), buffer.items[0]);
}

// Test 12: End Marker Message
test "3GPP TS 29.281 - End Marker" {
    const allocator = testing.allocator;

    var end_marker = gtpu.GtpuMessage.createEndMarker(allocator, 0x12345678, 999);
    defer end_marker.deinit();

    try testing.expectEqual(gtpu.protocol.MessageType.end_marker, end_marker.header.message_type);
    try testing.expectEqual(@as(u32, 0x12345678), end_marker.header.teid);
    try testing.expect(end_marker.header.flags.s);
    try testing.expectEqual(@as(u16, 999), end_marker.header.sequence_number.?);
}
