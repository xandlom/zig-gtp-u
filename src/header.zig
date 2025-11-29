// GTP-U Header Implementation
// 3GPP TS 29.281 Section 5

const std = @import("std");
const protocol = @import("protocol.zig");

// GTP-U Header Flags
pub const HeaderFlags = packed struct(u8) {
    pn: bool = false,      // N-PDU Number flag
    s: bool = false,       // Sequence Number flag
    e: bool = false,       // Extension Header flag
    spare: u1 = 0,         // Spare bit
    pt: u1 = 1,            // Protocol Type (always 1 for GTP)
    version: u3 = protocol.GTPU_VERSION,

    pub fn hasOptionalFields(self: HeaderFlags) bool {
        return self.pn or self.s or self.e;
    }
};

// GTP-U Header Structure
pub const GtpuHeader = struct {
    flags: HeaderFlags,
    message_type: protocol.MessageType,
    length: u16,           // Length of payload (not including mandatory header)
    teid: u32,             // Tunnel Endpoint Identifier

    // Optional fields (present if flags indicate)
    sequence_number: ?u16 = null,
    n_pdu_number: ?u8 = null,
    next_extension_type: ?protocol.ExtensionHeaderType = null,

    pub const MANDATORY_SIZE = 8;  // Bytes
    pub const OPTIONAL_SIZE = 4;   // Bytes (when present)

    pub fn init(message_type: protocol.MessageType, teid: u32) GtpuHeader {
        return .{
            .flags = .{},
            .message_type = message_type,
            .length = 0,
            .teid = teid,
        };
    }

    pub fn size(self: GtpuHeader) usize {
        var result: usize = MANDATORY_SIZE;
        if (self.flags.hasOptionalFields()) {
            result += OPTIONAL_SIZE;
        }
        return result;
    }

    pub fn encode(self: GtpuHeader, writer: anytype) !void {
        // Mandatory part (8 bytes)
        try writer.writeByte(@bitCast(self.flags));
        try writer.writeByte(@intFromEnum(self.message_type));
        try writer.writeInt(u16, self.length, .big);
        try writer.writeInt(u32, self.teid, .big);

        // Optional part (4 bytes)
        if (self.flags.hasOptionalFields()) {
            try writer.writeInt(u16, self.sequence_number orelse 0, .big);
            try writer.writeByte(self.n_pdu_number orelse 0);
            try writer.writeByte(if (self.next_extension_type) |ext| @intFromEnum(ext) else 0);
        }
    }

    pub fn decode(reader: anytype) !GtpuHeader {
        // Read mandatory part
        const flags: HeaderFlags = @bitCast(try reader.readByte());

        // Validate version
        if (flags.version != protocol.GTPU_VERSION) {
            return error.InvalidVersion;
        }

        const message_type: protocol.MessageType = @enumFromInt(try reader.readByte());
        const length = try reader.readInt(u16, .big);
        const teid = try reader.readInt(u32, .big);

        var header = GtpuHeader{
            .flags = flags,
            .message_type = message_type,
            .length = length,
            .teid = teid,
        };

        // Read optional part if present
        if (flags.hasOptionalFields()) {
            header.sequence_number = try reader.readInt(u16, .big);
            header.n_pdu_number = try reader.readByte();
            const next_ext = try reader.readByte();
            header.next_extension_type = if (next_ext != 0) @enumFromInt(next_ext) else null;
        }

        return header;
    }

    pub fn format(
        self: GtpuHeader,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("GTP-U Header:\n", .{});
        try writer.print("  Version: {}\n", .{self.flags.version});
        try writer.print("  Message Type: {} (0x{X:0>2})\n", .{ self.message_type, @intFromEnum(self.message_type) });
        try writer.print("  Length: {}\n", .{self.length});
        try writer.print("  TEID: 0x{X:0>8}\n", .{self.teid});

        if (self.sequence_number) |seq| {
            try writer.print("  Sequence: {}\n", .{seq});
        }
        if (self.n_pdu_number) |npdu| {
            try writer.print("  N-PDU: {}\n", .{npdu});
        }
        if (self.next_extension_type) |ext| {
            try writer.print("  Next Extension: {s}\n", .{ext.toString()});
        }
    }
};

test "GtpuHeader basic encode/decode" {
    const allocator = std.testing.allocator;

    var header = GtpuHeader.init(.g_pdu, 0x12345678);
    header.length = 100;

    // Encode
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    try header.encode(buffer.writer(allocator));

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try GtpuHeader.decode(stream.reader());

    try std.testing.expectEqual(header.flags.version, decoded.flags.version);
    try std.testing.expectEqual(header.message_type, decoded.message_type);
    try std.testing.expectEqual(header.length, decoded.length);
    try std.testing.expectEqual(header.teid, decoded.teid);
}

test "GtpuHeader with optional fields" {
    const allocator = std.testing.allocator;

    var header = GtpuHeader.init(.g_pdu, 0x12345678);
    header.length = 100;
    header.flags.s = true;
    header.flags.e = true;
    header.sequence_number = 42;
    header.next_extension_type = .pdcp_pdu_number;

    // Encode
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    try header.encode(buffer.writer(allocator));

    // Verify size
    try std.testing.expectEqual(GtpuHeader.MANDATORY_SIZE + GtpuHeader.OPTIONAL_SIZE, buffer.items.len);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try GtpuHeader.decode(stream.reader());

    try std.testing.expectEqual(header.sequence_number, decoded.sequence_number);
    try std.testing.expectEqual(header.next_extension_type, decoded.next_extension_type);
}
