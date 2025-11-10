// GTP-U Information Elements
// 3GPP TS 29.281 Section 8

const std = @import("std");

// IE Type identifiers
pub const IEType = enum(u8) {
    recovery = 14,
    tunnel_endpoint_identifier = 16,
    gtp_user_plane_pdcp_pdu_number = 18,
    gsn_address = 133,
    extension_header_type_list = 141,
    private_extension = 255,
    _,
};

// Cause values for Error Indication
pub const Cause = enum(u8) {
    request_accepted = 128,
    new_pdn_prefix = 129,
    new_apn_restriction = 130,

    // Error causes
    context_not_found = 192,
    invalid_length = 193,
    service_not_supported = 194,
    mandatory_ie_missing = 195,
    system_failure = 204,

    _,
};

// QoS Profile structure (simplified)
pub const QosProfile = struct {
    qci: u8,  // QoS Class Identifier
    arp: u8,  // Allocation and Retention Priority
    gbr_uplink: u64,   // Guaranteed Bit Rate Uplink (bps)
    gbr_downlink: u64, // Guaranteed Bit Rate Downlink (bps)
    mbr_uplink: u64,   // Maximum Bit Rate Uplink (bps)
    mbr_downlink: u64, // Maximum Bit Rate Downlink (bps)
};

// User Location Information (simplified for 5G)
pub const UserLocationInfo = struct {
    mcc: u16,  // Mobile Country Code
    mnc: u16,  // Mobile Network Code
    tac: u32,  // Tracking Area Code
    cell_id: u64,  // Cell Identity
};

// Information Element
pub const InformationElement = union(IEType) {
    recovery: u8,
    tunnel_endpoint_identifier: u32,
    gtp_user_plane_pdcp_pdu_number: u16,
    gsn_address: []const u8,
    extension_header_type_list: []const u8,
    private_extension: PrivateExtension,

    pub const PrivateExtension = struct {
        enterprise_id: u16,
        value: []const u8,
    };

    pub fn deinit(self: *InformationElement, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .gsn_address => |addr| allocator.free(addr),
            .extension_header_type_list => |list| allocator.free(list),
            .private_extension => |ext| allocator.free(ext.value),
            else => {},
        }
    }

    pub fn initRecovery(restart_counter: u8) InformationElement {
        return .{ .recovery = restart_counter };
    }

    pub fn initTeid(teid: u32) InformationElement {
        return .{ .tunnel_endpoint_identifier = teid };
    }

    pub fn initPeerAddress(allocator: std.mem.Allocator, address: std.net.Address) !InformationElement {
        const addr_bytes = switch (address.any.family) {
            std.posix.AF.INET => blk: {
                const bytes = try allocator.alloc(u8, 4);
                @memcpy(bytes, &address.in.sa.addr);
                break :blk bytes;
            },
            std.posix.AF.INET6 => blk: {
                const bytes = try allocator.alloc(u8, 16);
                @memcpy(bytes, &address.in6.sa.addr);
                break :blk bytes;
            },
            else => return error.UnsupportedAddressFamily,
        };

        return .{
            .gsn_address = addr_bytes,
        };
    }

    pub fn size(self: InformationElement) usize {
        // Type (1 byte) + Length (2 bytes) + Value
        var value_size: usize = 0;

        switch (self) {
            .recovery => value_size = 1,
            .tunnel_endpoint_identifier => value_size = 4,
            .gtp_user_plane_pdcp_pdu_number => value_size = 2,
            .gsn_address => |addr| value_size = addr.len,
            .extension_header_type_list => |list| value_size = list.len,
            .private_extension => |ext| value_size = 2 + ext.value.len, // enterprise_id + value
            else => value_size = 0,
        }

        return 1 + 2 + value_size; // type + length + value
    }

    pub fn encode(self: InformationElement, writer: anytype) !void {
        const ie_type: IEType = self;
        try writer.writeByte(@intFromEnum(ie_type));

        // Calculate and write length
        const value_size = self.size() - 3; // Exclude type and length fields
        try writer.writeInt(u16, @intCast(value_size), .big);

        // Write value
        switch (self) {
            .recovery => |val| try writer.writeByte(val),
            .tunnel_endpoint_identifier => |val| try writer.writeInt(u32, val, .big),
            .gtp_user_plane_pdcp_pdu_number => |val| try writer.writeInt(u16, val, .big),
            .gsn_address => |addr| try writer.writeAll(addr),
            .extension_header_type_list => |list| try writer.writeAll(list),
            .private_extension => |ext| {
                try writer.writeInt(u16, ext.enterprise_id, .big);
                try writer.writeAll(ext.value);
            },
            else => {},
        }
    }

    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !InformationElement {
        const ie_type: IEType = @enumFromInt(try reader.readByte());
        const length = try reader.readInt(u16, .big);

        return switch (ie_type) {
            .recovery => .{
                .recovery = try reader.readByte(),
            },
            .tunnel_endpoint_identifier => .{
                .tunnel_endpoint_identifier = try reader.readInt(u32, .big),
            },
            .gtp_user_plane_pdcp_pdu_number => .{
                .gtp_user_plane_pdcp_pdu_number = try reader.readInt(u16, .big),
            },
            .gsn_address => blk: {
                const addr = try allocator.alloc(u8, length);
                const bytes_read = try reader.readAll(addr);
                if (bytes_read != length) {
                    allocator.free(addr);
                    return error.UnexpectedEof;
                }
                break :blk .{
                    .gsn_address = addr,
                };
            },
            .extension_header_type_list => blk: {
                const list = try allocator.alloc(u8, length);
                const bytes_read = try reader.readAll(list);
                if (bytes_read != length) {
                    allocator.free(list);
                    return error.UnexpectedEof;
                }
                break :blk .{
                    .extension_header_type_list = list,
                };
            },
            .private_extension => blk: {
                const enterprise_id = try reader.readInt(u16, .big);
                const value_len = length - 2;
                const value = try allocator.alloc(u8, value_len);
                const bytes_read = try reader.readAll(value);
                if (bytes_read != value_len) {
                    allocator.free(value);
                    return error.UnexpectedEof;
                }
                break :blk .{
                    .private_extension = .{
                        .enterprise_id = enterprise_id,
                        .value = value,
                    },
                };
            },
            else => @panic("Unknown IE type"),
        };
    }
};

test "IE Recovery encode/decode" {
    const allocator = std.testing.allocator;

    const ie = InformationElement.initRecovery(42);

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try ie.encode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try InformationElement.decode(allocator, stream.reader());
    defer decoded.deinit();

    try std.testing.expectEqual(IEType.recovery, decoded);
    try std.testing.expectEqual(@as(u8, 42), decoded.recovery);
}
