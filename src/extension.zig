// GTP-U Extension Headers
// 3GPP TS 29.281 Section 5.2

const std = @import("std");
const protocol = @import("protocol.zig");

pub const ExtensionHeaderType = protocol.ExtensionHeaderType;

// PDU Session Container for 5G
pub const PduSessionContainer = struct {
    pdu_type: u4,       // PDU Type (0=DL, 1=UL)
    qfi: u6,            // QoS Flow Identifier
    ppi: u3,            // Paging Policy Indicator
    rqi: bool,          // Reflective QoS Indicator
    spare: u8 = 0,

    pub fn encode(self: PduSessionContainer, writer: anytype) !void {
        const byte1 = (@as(u8, self.pdu_type) << 4) | (@as(u8, self.qfi >> 2));
        const byte2 = (@as(u8, @as(u2, @truncate(self.qfi))) << 6) |
                      (@as(u8, self.ppi) << 3) |
                      (@as(u8, @intFromBool(self.rqi)) << 2);
        try writer.writeByte(byte1);
        try writer.writeByte(byte2);
    }

    pub fn decode(reader: anytype) !PduSessionContainer {
        const byte1 = try reader.readByte();
        const byte2 = try reader.readByte();

        return .{
            .pdu_type = @truncate(byte1 >> 4),
            .qfi = (@as(u6, @truncate(byte1)) << 2) | @as(u6, @truncate(byte2 >> 6)),
            .ppi = @truncate(byte2 >> 3),
            .rqi = (byte2 & 0x04) != 0,
        };
    }
};

// PDCP PDU Number
pub const PdcpPduNumber = struct {
    pdu_number: u16,

    pub fn encode(self: PdcpPduNumber, writer: anytype) !void {
        try writer.writeInt(u16, self.pdu_number, .big);
    }

    pub fn decode(reader: anytype) !PdcpPduNumber {
        return .{
            .pdu_number = try reader.readInt(u16, .big),
        };
    }
};

// Long PDCP PDU Number (for UM DRBs)
pub const LongPdcpPduNumber = struct {
    pdu_number: u24,

    pub fn encode(self: LongPdcpPduNumber, writer: anytype) !void {
        try writer.writeByte(@truncate(self.pdu_number >> 16));
        try writer.writeByte(@truncate(self.pdu_number >> 8));
        try writer.writeByte(@truncate(self.pdu_number));
    }

    pub fn decode(reader: anytype) !LongPdcpPduNumber {
        const b1 = try reader.readByte();
        const b2 = try reader.readByte();
        const b3 = try reader.readByte();

        return .{
            .pdu_number = (@as(u24, b1) << 16) | (@as(u24, b2) << 8) | b3,
        };
    }
};

// Service Class Indicator
pub const ServiceClassIndicator = struct {
    service_class: u8,

    pub fn encode(self: ServiceClassIndicator, writer: anytype) !void {
        try writer.writeByte(self.service_class);
    }

    pub fn decode(reader: anytype) !ServiceClassIndicator {
        return .{
            .service_class = try reader.readByte(),
        };
    }
};

// UDP Port
pub const UdpPortExtension = struct {
    port: u16,

    pub fn encode(self: UdpPortExtension, writer: anytype) !void {
        try writer.writeInt(u16, self.port, .big);
    }

    pub fn decode(reader: anytype) !UdpPortExtension {
        return .{
            .port = try reader.readInt(u16, .big),
        };
    }
};

// RAN Container (opaque bytes)
pub const RanContainer = struct {
    data: []const u8,
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *RanContainer) void {
        if (self.allocator) |allocator| {
            allocator.free(self.data);
        }
    }

    pub fn encode(self: RanContainer, writer: anytype) !void {
        try writer.writeAll(self.data);
    }

    pub fn decode(allocator: std.mem.Allocator, reader: anytype, length: usize) !RanContainer {
        const data = try allocator.alloc(u8, length);
        const bytes_read = try reader.readAll(data);
        if (bytes_read != length) {
            allocator.free(data);
            return error.UnexpectedEof;
        }
        return .{
            .data = data,
            .allocator = allocator,
        };
    }
};

// Data Delivery Status (5G)
// Used to indicate delivery status of user plane data
pub const DataDeliveryStatus = struct {
    // Bit fields as per 3GPP TS 29.281
    highest_delivered_pdcp_sn: u16,  // PDCP sequence number
    highest_retransmitted_pdcp_sn: u16,  // Retransmitted PDCP SN
    final_frame_indication: bool,  // Final frame indicator
    spare: u3 = 0,

    pub fn encode(self: DataDeliveryStatus, writer: anytype) !void {
        try writer.writeInt(u16, self.highest_delivered_pdcp_sn, .big);
        try writer.writeInt(u16, self.highest_retransmitted_pdcp_sn, .big);
        const flags = (@as(u8, @intFromBool(self.final_frame_indication)) << 7) | self.spare;
        try writer.writeByte(flags);
    }

    pub fn decode(reader: anytype) !DataDeliveryStatus {
        const highest_delivered = try reader.readInt(u16, .big);
        const highest_retransmitted = try reader.readInt(u16, .big);
        const flags = try reader.readByte();

        return .{
            .highest_delivered_pdcp_sn = highest_delivered,
            .highest_retransmitted_pdcp_sn = highest_retransmitted,
            .final_frame_indication = (flags & 0x80) != 0,
            .spare = @truncate(flags & 0x07),
        };
    }
};

// Delay Indication (5G)
// Used to convey delay budget information
pub const DelayIndication = struct {
    delay_value: u32,  // Delay in milliseconds

    pub fn encode(self: DelayIndication, writer: anytype) !void {
        try writer.writeInt(u32, self.delay_value, .big);
    }

    pub fn decode(reader: anytype) !DelayIndication {
        return .{
            .delay_value = try reader.readInt(u32, .big),
        };
    }
};

// Buffering Suggested Packets Count (5G)
pub const BufferingSuggestedPacketsCount = struct {
    packet_count: u8,  // Suggested number of packets to buffer

    pub fn encode(self: BufferingSuggestedPacketsCount, writer: anytype) !void {
        try writer.writeByte(self.packet_count);
    }

    pub fn decode(reader: anytype) !BufferingSuggestedPacketsCount {
        return .{
            .packet_count = try reader.readByte(),
        };
    }
};

// Buffering Duration (5G)
pub const BufferingDuration = struct {
    duration_ms: u32,  // Buffering duration in milliseconds

    pub fn encode(self: BufferingDuration, writer: anytype) !void {
        try writer.writeInt(u32, self.duration_ms, .big);
    }

    pub fn decode(reader: anytype) !BufferingDuration {
        return .{
            .duration_ms = try reader.readInt(u32, .big),
        };
    }
};

// Sending Time (5G)
// NTP timestamp format (seconds and fractional seconds)
pub const SendingTime = struct {
    timestamp_seconds: u32,      // NTP timestamp seconds since 1900
    timestamp_fraction: u32,     // NTP fractional seconds

    pub fn encode(self: SendingTime, writer: anytype) !void {
        try writer.writeInt(u32, self.timestamp_seconds, .big);
        try writer.writeInt(u32, self.timestamp_fraction, .big);
    }

    pub fn decode(reader: anytype) !SendingTime {
        return .{
            .timestamp_seconds = try reader.readInt(u32, .big),
            .timestamp_fraction = try reader.readInt(u32, .big),
        };
    }
};

// Extension Header union
pub const ExtensionHeader = union(ExtensionHeaderType) {
    no_more_headers: void,
    reserved: void,
    mbms_support_indication: void,
    service_class_indicator: ServiceClassIndicator,
    udp_port: UdpPortExtension,
    ran_container: RanContainer,
    long_pdcp_pdu_number: LongPdcpPduNumber,
    xw_ran_container: RanContainer,
    nr_ran_container: RanContainer,
    pdu_session_container: PduSessionContainer,
    dl_data_delivery_status: DataDeliveryStatus,
    ul_data_delivery_status: DataDeliveryStatus,
    dl_delay: DelayIndication,
    ul_delay: DelayIndication,
    dl_buffering_suggested_packets_count: BufferingSuggestedPacketsCount,
    dl_buffering_duration: BufferingDuration,
    dl_sending_time: SendingTime,
    ul_sending_time: SendingTime,
    pdcp_pdu_number: PdcpPduNumber,
    suspend_request: void,
    suspend_response: void,

    pub fn deinit(self: *ExtensionHeader) void {
        switch (self.*) {
            .ran_container => |*rc| rc.deinit(),
            .xw_ran_container => |*rc| rc.deinit(),
            .nr_ran_container => |*rc| rc.deinit(),
            else => {},
        }
    }

    pub fn size(self: ExtensionHeader) usize {
        // Extension header format: length (1 byte) + content + padding + next type (1 byte)
        // Total size = length * 4 (length field value times 4)
        // The length field includes itself in the count
        const content_size = switch (self) {
            .pdu_session_container => 2,
            .pdcp_pdu_number => 2,
            .long_pdcp_pdu_number => 3,
            .service_class_indicator => 1,
            .udp_port => 2,
            .ran_container => |rc| rc.data.len,
            .xw_ran_container => |rc| rc.data.len,
            .nr_ran_container => |rc| rc.data.len,
            .dl_data_delivery_status => 5,  // 2 + 2 + 1 bytes
            .ul_data_delivery_status => 5,  // 2 + 2 + 1 bytes
            .dl_delay => 4,  // 4 bytes for u32
            .ul_delay => 4,  // 4 bytes for u32
            .dl_buffering_suggested_packets_count => 1,  // 1 byte
            .dl_buffering_duration => 4,  // 4 bytes for u32
            .dl_sending_time => 8,  // 8 bytes for NTP timestamp
            .ul_sending_time => 8,  // 8 bytes for NTP timestamp
            else => 0,
        };

        // Calculate units: need to fit length(1) + content + next_type(1) in units*4 bytes
        // units * 4 >= 1 + content_size + 1
        // units >= (content_size + 2) / 4
        const units = (content_size + 2 + 3) / 4; // +2 for length and next_type, +3 for ceiling
        return units * 4; // Total size is always multiple of 4
    }

    pub fn encode(self: ExtensionHeader, writer: anytype, next_ext_type: ?ExtensionHeaderType) !void {
        const content_size = switch (self) {
            .pdu_session_container => 2,
            .pdcp_pdu_number => 2,
            .long_pdcp_pdu_number => 3,
            .service_class_indicator => 1,
            .udp_port => 2,
            .ran_container => |rc| rc.data.len,
            .xw_ran_container => |rc| rc.data.len,
            .nr_ran_container => |rc| rc.data.len,
            .dl_data_delivery_status => 5,
            .ul_data_delivery_status => 5,
            .dl_delay => 4,
            .ul_delay => 4,
            .dl_buffering_suggested_packets_count => 1,
            .dl_buffering_duration => 4,
            .dl_sending_time => 8,
            .ul_sending_time => 8,
            else => 0,
        };

        // Calculate length in 4-byte units
        // Total bytes needed: length(1) + content + next_type(1)
        const units: u8 = @intCast((content_size + 2 + 3) / 4); // +2 for length and next_type, +3 for ceiling
        try writer.writeByte(units);

        // Write content
        switch (self) {
            .pdu_session_container => |psc| try psc.encode(writer),
            .pdcp_pdu_number => |ppn| try ppn.encode(writer),
            .long_pdcp_pdu_number => |lppn| try lppn.encode(writer),
            .service_class_indicator => |sci| try sci.encode(writer),
            .udp_port => |up| try up.encode(writer),
            .ran_container => |rc| try rc.encode(writer),
            .xw_ran_container => |rc| try rc.encode(writer),
            .nr_ran_container => |rc| try rc.encode(writer),
            .dl_data_delivery_status => |dds| try dds.encode(writer),
            .ul_data_delivery_status => |dds| try dds.encode(writer),
            .dl_delay => |di| try di.encode(writer),
            .ul_delay => |di| try di.encode(writer),
            .dl_buffering_suggested_packets_count => |bspc| try bspc.encode(writer),
            .dl_buffering_duration => |bd| try bd.encode(writer),
            .dl_sending_time => |st| try st.encode(writer),
            .ul_sending_time => |st| try st.encode(writer),
            else => {},
        }

        // Write padding to align to 4-byte boundary
        // Total size: units * 4
        // Already written: 1 (length) + content_size
        // Still need: next_type (1) + padding
        const total_size = @as(usize, units) * 4;
        const already_written = 1 + content_size; // length + content
        const remaining = total_size - already_written; // This includes next_type + padding
        const padding_size = remaining - 1; // -1 for next_type

        var i: usize = 0;
        while (i < padding_size) : (i += 1) {
            try writer.writeByte(0);
        }

        // Write next extension type
        const next = next_ext_type orelse ExtensionHeaderType.no_more_headers;
        try writer.writeByte(@intFromEnum(next));
    }

    pub const DecodeResult = struct {
        header: ExtensionHeader,
        next_type: ExtensionHeaderType,
    };

    pub fn decode(reader: anytype, ext_type: ExtensionHeaderType) !DecodeResult {
        const length = try reader.readByte(); // Length in 4-byte units
        // Total size is length * 4, which includes the length byte itself
        // Content size = total - length byte - next_type byte
        const content_size = (length * 4) - 1 - 1; // -1 for length byte, -1 for next_type byte

        // Create a limited reader for the content
        var limited = std.io.limitedReader(reader, content_size);
        const lim_reader = limited.reader();

        const header: ExtensionHeader = switch (ext_type) {
            .pdu_session_container => .{
                .pdu_session_container = try PduSessionContainer.decode(lim_reader),
            },
            .pdcp_pdu_number => .{
                .pdcp_pdu_number = try PdcpPduNumber.decode(lim_reader),
            },
            .long_pdcp_pdu_number => .{
                .long_pdcp_pdu_number = try LongPdcpPduNumber.decode(lim_reader),
            },
            .service_class_indicator => .{
                .service_class_indicator = try ServiceClassIndicator.decode(lim_reader),
            },
            .udp_port => .{
                .udp_port = try UdpPortExtension.decode(lim_reader),
            },
            .dl_data_delivery_status => .{
                .dl_data_delivery_status = try DataDeliveryStatus.decode(lim_reader),
            },
            .ul_data_delivery_status => .{
                .ul_data_delivery_status = try DataDeliveryStatus.decode(lim_reader),
            },
            .dl_delay => .{
                .dl_delay = try DelayIndication.decode(lim_reader),
            },
            .ul_delay => .{
                .ul_delay = try DelayIndication.decode(lim_reader),
            },
            .dl_buffering_suggested_packets_count => .{
                .dl_buffering_suggested_packets_count = try BufferingSuggestedPacketsCount.decode(lim_reader),
            },
            .dl_buffering_duration => .{
                .dl_buffering_duration = try BufferingDuration.decode(lim_reader),
            },
            .dl_sending_time => .{
                .dl_sending_time = try SendingTime.decode(lim_reader),
            },
            .ul_sending_time => .{
                .ul_sending_time = try SendingTime.decode(lim_reader),
            },
            else => @panic("Unknown extension header type"),
        };

        // Skip any remaining padding
        const remaining = limited.bytes_left;
        var i: usize = 0;
        while (i < remaining) : (i += 1) {
            _ = try reader.readByte();
        }

        // Read next extension type
        const next_type_byte = try reader.readByte();
        const next_type: ExtensionHeaderType = if (next_type_byte == 0)
            .no_more_headers
        else
            @enumFromInt(next_type_byte);

        return .{
            .header = header,
            .next_type = next_type,
        };
    }
};

test "PDU Session Container encode/decode" {
    const allocator = std.testing.allocator;

    const psc = PduSessionContainer{
        .pdu_type = 1,  // UL
        .qfi = 9,       // QFI 9
        .ppi = 0,
        .rqi = true,
    };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try psc.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try PduSessionContainer.decode(stream.reader());

    try std.testing.expectEqual(psc.pdu_type, decoded.pdu_type);
    try std.testing.expectEqual(psc.qfi, decoded.qfi);
    try std.testing.expectEqual(psc.rqi, decoded.rqi);
}

test "PDCP PDU Number encode/decode" {
    const allocator = std.testing.allocator;

    const ppn = PdcpPduNumber{ .pdu_number = 12345 };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ppn.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try PdcpPduNumber.decode(stream.reader());

    try std.testing.expectEqual(ppn.pdu_number, decoded.pdu_number);
}

test "Extension Header full encode/decode" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .pdcp_pdu_number = .{ .pdu_number = 999 },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null); // null means this is the last extension

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .pdcp_pdu_number);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.pdcp_pdu_number, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u16, 999), decode_result.header.pdcp_pdu_number.pdu_number);
    try std.testing.expectEqual(ExtensionHeaderType.no_more_headers, decode_result.next_type);
}

// ===== Tests for 5G Extension Headers =====

test "Data Delivery Status encode/decode" {
    const allocator = std.testing.allocator;

    const dds = DataDeliveryStatus{
        .highest_delivered_pdcp_sn = 12345,
        .highest_retransmitted_pdcp_sn = 12300,
        .final_frame_indication = true,
    };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try dds.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try DataDeliveryStatus.decode(stream.reader());

    try std.testing.expectEqual(dds.highest_delivered_pdcp_sn, decoded.highest_delivered_pdcp_sn);
    try std.testing.expectEqual(dds.highest_retransmitted_pdcp_sn, decoded.highest_retransmitted_pdcp_sn);
    try std.testing.expectEqual(dds.final_frame_indication, decoded.final_frame_indication);
}

test "DL Data Delivery Status Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .dl_data_delivery_status = .{
            .highest_delivered_pdcp_sn = 65535,
            .highest_retransmitted_pdcp_sn = 65000,
            .final_frame_indication = false,
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .dl_data_delivery_status);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_data_delivery_status, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u16, 65535), decode_result.header.dl_data_delivery_status.highest_delivered_pdcp_sn);
    try std.testing.expectEqual(@as(u16, 65000), decode_result.header.dl_data_delivery_status.highest_retransmitted_pdcp_sn);
    try std.testing.expectEqual(false, decode_result.header.dl_data_delivery_status.final_frame_indication);
}

test "Delay Indication encode/decode" {
    const allocator = std.testing.allocator;

    const delay = DelayIndication{
        .delay_value = 500,  // 500 ms
    };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try delay.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try DelayIndication.decode(stream.reader());

    try std.testing.expectEqual(delay.delay_value, decoded.delay_value);
}

test "DL Delay Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .dl_delay = .{
            .delay_value = 1000,  // 1000 ms
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .dl_delay);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_delay, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u32, 1000), decode_result.header.dl_delay.delay_value);
}

test "UL Delay Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .ul_delay = .{
            .delay_value = 250,  // 250 ms
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .ul_delay);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.ul_delay, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u32, 250), decode_result.header.ul_delay.delay_value);
}

test "Buffering Suggested Packets Count encode/decode" {
    const allocator = std.testing.allocator;

    const bspc = BufferingSuggestedPacketsCount{
        .packet_count = 42,
    };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try bspc.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try BufferingSuggestedPacketsCount.decode(stream.reader());

    try std.testing.expectEqual(bspc.packet_count, decoded.packet_count);
}

test "DL Buffering Suggested Packets Count Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .dl_buffering_suggested_packets_count = .{
            .packet_count = 128,
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .dl_buffering_suggested_packets_count);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_buffering_suggested_packets_count, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u8, 128), decode_result.header.dl_buffering_suggested_packets_count.packet_count);
}

test "Buffering Duration encode/decode" {
    const allocator = std.testing.allocator;

    const bd = BufferingDuration{
        .duration_ms = 5000,  // 5 seconds
    };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try bd.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try BufferingDuration.decode(stream.reader());

    try std.testing.expectEqual(bd.duration_ms, decoded.duration_ms);
}

test "DL Buffering Duration Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .dl_buffering_duration = .{
            .duration_ms = 10000,  // 10 seconds
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .dl_buffering_duration);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_buffering_duration, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u32, 10000), decode_result.header.dl_buffering_duration.duration_ms);
}

test "Sending Time encode/decode" {
    const allocator = std.testing.allocator;

    const st = SendingTime{
        .timestamp_seconds = 3912345678,
        .timestamp_fraction = 2147483648,
    };

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try st.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try SendingTime.decode(stream.reader());

    try std.testing.expectEqual(st.timestamp_seconds, decoded.timestamp_seconds);
    try std.testing.expectEqual(st.timestamp_fraction, decoded.timestamp_fraction);
}

test "DL Sending Time Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .dl_sending_time = .{
            .timestamp_seconds = 3912345678,
            .timestamp_fraction = 1073741824,
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .dl_sending_time);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_sending_time, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u32, 3912345678), decode_result.header.dl_sending_time.timestamp_seconds);
    try std.testing.expectEqual(@as(u32, 1073741824), decode_result.header.dl_sending_time.timestamp_fraction);
}

test "UL Sending Time Extension Header" {
    const allocator = std.testing.allocator;

    var ext: ExtensionHeader = .{
        .ul_sending_time = .{
            .timestamp_seconds = 3912345679,
            .timestamp_fraction = 2147483648,
        },
    };
    defer ext.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext.encode(buffer.writer(), null);

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decode_result = try ExtensionHeader.decode(stream.reader(), .ul_sending_time);
    defer decode_result.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.ul_sending_time, @as(ExtensionHeaderType, decode_result.header));
    try std.testing.expectEqual(@as(u32, 3912345679), decode_result.header.ul_sending_time.timestamp_seconds);
    try std.testing.expectEqual(@as(u32, 2147483648), decode_result.header.ul_sending_time.timestamp_fraction);
}

test "Multiple 5G Extension Headers chained" {
    const allocator = std.testing.allocator;

    // Test chaining: DL Delay -> DL Data Delivery Status -> No more
    var ext1: ExtensionHeader = .{
        .dl_delay = .{ .delay_value = 500 },
    };
    defer ext1.deinit();

    var ext2: ExtensionHeader = .{
        .dl_data_delivery_status = .{
            .highest_delivered_pdcp_sn = 100,
            .highest_retransmitted_pdcp_sn = 90,
            .final_frame_indication = true,
        },
    };
    defer ext2.deinit();

    // Encode both headers
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ext1.encode(buffer.writer(), .dl_data_delivery_status);
    try ext2.encode(buffer.writer(), null);

    // Decode first header
    var stream = std.io.fixedBufferStream(buffer.items);
    var result1 = try ExtensionHeader.decode(stream.reader(), .dl_delay);
    defer result1.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_delay, @as(ExtensionHeaderType, result1.header));
    try std.testing.expectEqual(@as(u32, 500), result1.header.dl_delay.delay_value);
    try std.testing.expectEqual(ExtensionHeaderType.dl_data_delivery_status, result1.next_type);

    // Decode second header
    var result2 = try ExtensionHeader.decode(stream.reader(), result1.next_type);
    defer result2.header.deinit();

    try std.testing.expectEqual(ExtensionHeaderType.dl_data_delivery_status, @as(ExtensionHeaderType, result2.header));
    try std.testing.expectEqual(@as(u16, 100), result2.header.dl_data_delivery_status.highest_delivered_pdcp_sn);
    try std.testing.expectEqual(ExtensionHeaderType.no_more_headers, result2.next_type);
}
