// GTP-U Message Implementation
// 3GPP TS 29.281 Section 5

const std = @import("std");
const protocol = @import("protocol.zig");
const header = @import("header.zig");
const ie = @import("ie.zig");
const extension = @import("extension.zig");

pub const MessageType = protocol.MessageType;

// GTP-U Message Structure
pub const GtpuMessage = struct {
    header: header.GtpuHeader,
    extension_headers: std.ArrayList(extension.ExtensionHeader),
    information_elements: std.ArrayList(ie.InformationElement),
    payload: []const u8,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, message_type: MessageType, teid: u32) GtpuMessage {
        return .{
            .header = header.GtpuHeader.init(message_type, teid),
            .extension_headers = std.ArrayList(extension.ExtensionHeader).init(allocator),
            .information_elements = std.ArrayList(ie.InformationElement).init(allocator),
            .payload = &[_]u8{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GtpuMessage) void {
        self.extension_headers.deinit();
        for (self.information_elements.items) |*elem| {
            elem.deinit(self.allocator);
        }
        self.information_elements.deinit();
    }

    pub fn setPayload(self: *GtpuMessage, payload: []const u8) void {
        self.payload = payload;
        self.updateLength();
    }

    pub fn addExtensionHeader(self: *GtpuMessage, ext: extension.ExtensionHeader) !void {
        try self.extension_headers.append(ext);
        self.header.flags.e = true;
        self.updateLength();
    }

    pub fn addInformationElement(self: *GtpuMessage, elem: ie.InformationElement) !void {
        try self.information_elements.append(elem);
        self.updateLength();
    }

    fn updateLength(self: *GtpuMessage) void {
        var length: usize = 0;

        // Optional header fields
        if (self.header.flags.hasOptionalFields()) {
            length += 4;
        }

        // Extension headers
        for (self.extension_headers.items) |ext| {
            length += ext.size();
        }

        // Information elements
        for (self.information_elements.items) |elem| {
            length += elem.size();
        }

        // Payload
        length += self.payload.len;

        self.header.length = @intCast(length);
    }

    pub fn encode(self: *GtpuMessage, writer: anytype) !void {
        // Update length before encoding
        self.updateLength();

        // Encode header
        try self.header.encode(writer);

        // Encode extension headers
        for (self.extension_headers.items, 0..) |ext, i| {
            const is_last = (i == self.extension_headers.items.len - 1);
            try ext.encode(writer, is_last);
        }

        // Encode information elements
        for (self.information_elements.items) |elem| {
            try elem.encode(writer);
        }

        // Encode payload
        try writer.writeAll(self.payload);
    }

    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !GtpuMessage {
        // Decode header
        const hdr = try header.GtpuHeader.decode(reader);

        var msg = GtpuMessage.init(allocator, hdr.message_type, hdr.teid);
        msg.header = hdr;

        var remaining_length: usize = hdr.length;

        // Decode extension headers if present
        if (hdr.flags.e) {
            var next_type = hdr.next_extension_type orelse .no_more_headers;

            while (next_type != .no_more_headers) {
                const ext = try extension.ExtensionHeader.decode(reader, next_type);
                const ext_size = ext.size();
                if (ext_size > remaining_length) return error.InvalidLength;
                remaining_length -= ext_size;

                // Read next extension type from the wire (after the extension data)
                next_type = .no_more_headers; // For now, only support single extension
                try msg.extension_headers.append(ext);
            }
        }

        // For G-PDU, the rest is payload
        if (hdr.message_type == .g_pdu) {
            const payload_buf = try allocator.alloc(u8, remaining_length);
            const bytes_read = try reader.readAll(payload_buf);
            if (bytes_read != remaining_length) {
                allocator.free(payload_buf);
                return error.UnexpectedEof;
            }
            msg.payload = payload_buf;
        } else {
            // For other message types, decode IEs
            while (remaining_length > 0) {
                const elem = try ie.InformationElement.decode(allocator, reader);
                const elem_size = elem.size();
                if (elem_size > remaining_length) return error.InvalidLength;
                remaining_length -= elem_size;
                try msg.information_elements.append(elem);
            }
        }

        return msg;
    }

    pub fn createEchoRequest(allocator: std.mem.Allocator, sequence: u16) !GtpuMessage {
        var msg = GtpuMessage.init(allocator, .echo_request, 0);
        msg.header.flags.s = true;
        msg.header.sequence_number = sequence;
        return msg;
    }

    pub fn createEchoResponse(allocator: std.mem.Allocator, sequence: u16) !GtpuMessage {
        var msg = GtpuMessage.init(allocator, .echo_response, 0);
        msg.header.flags.s = true;
        msg.header.sequence_number = sequence;

        // Add Recovery IE
        const recovery = ie.InformationElement.initRecovery(0);
        try msg.addInformationElement(recovery);

        return msg;
    }

    pub fn createGpdu(allocator: std.mem.Allocator, teid: u32, payload: []const u8) GtpuMessage {
        var msg = GtpuMessage.init(allocator, .g_pdu, teid);
        msg.setPayload(payload);
        return msg;
    }

    pub fn createEndMarker(allocator: std.mem.Allocator, teid: u32, sequence: u16) GtpuMessage {
        var msg = GtpuMessage.init(allocator, .end_marker, teid);
        msg.header.flags.s = true;
        msg.header.sequence_number = sequence;
        return msg;
    }

    pub fn createErrorIndication(
        allocator: std.mem.Allocator,
        teid: u32,
        peer_address: std.net.Address,
    ) !GtpuMessage {
        var msg = GtpuMessage.init(allocator, .error_indication, teid);

        // Add Peer Address IE
        const peer_addr_ie = try ie.InformationElement.initPeerAddress(allocator, peer_address);
        try msg.addInformationElement(peer_addr_ie);

        return msg;
    }
};

test "GtpuMessage echo request/response" {
    const allocator = std.testing.allocator;

    // Create echo request
    var request = try GtpuMessage.createEchoRequest(allocator, 123);
    defer request.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try request.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try GtpuMessage.decode(allocator, stream.reader());
    defer decoded.deinit();

    try std.testing.expectEqual(MessageType.echo_request, decoded.header.message_type);
    try std.testing.expectEqual(@as(u16, 123), decoded.header.sequence_number.?);
}

test "GtpuMessage G-PDU" {
    const allocator = std.testing.allocator;

    const payload = "Hello, GTP-U!";
    var msg = GtpuMessage.createGpdu(allocator, 0x12345678, payload);
    defer msg.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try msg.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try GtpuMessage.decode(allocator, stream.reader());
    defer decoded.deinit();

    try std.testing.expectEqual(MessageType.g_pdu, decoded.header.message_type);
    try std.testing.expectEqual(@as(u32, 0x12345678), decoded.header.teid);
    try std.testing.expectEqualStrings(payload, decoded.payload);
}
