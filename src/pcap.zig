// PCAP file generation for Wireshark analysis
// Implements libpcap format for capturing GTP-U traffic
// Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat

const std = @import("std");

/// PCAP file writer for capturing network traffic
pub const PcapWriter = struct {
    file: std.fs.File,
    mutex: std.Thread.Mutex,
    packets_written: u64,

    /// PCAP global header magic number (little-endian)
    const PCAP_MAGIC: u32 = 0xa1b2c3d4;
    const VERSION_MAJOR: u16 = 2;
    const VERSION_MINOR: u16 = 4;
    const SNAPLEN: u32 = 65535; // Maximum capture length
    const LINKTYPE_ETHERNET: u32 = 1;

    /// PCAP global header (24 bytes)
    const GlobalHeader = packed struct {
        magic_number: u32, // Magic number
        version_major: u16, // Major version number
        version_minor: u16, // Minor version number
        thiszone: i32, // GMT to local correction
        sigfigs: u32, // Accuracy of timestamps
        snaplen: u32, // Max length of captured packets
        network: u32, // Data link type (Ethernet=1)
    };

    /// PCAP packet header (16 bytes)
    const PacketHeader = packed struct {
        ts_sec: u32, // Timestamp seconds
        ts_usec: u32, // Timestamp microseconds
        incl_len: u32, // Number of octets captured
        orig_len: u32, // Actual length of packet
    };

    /// Ethernet header (14 bytes)
    const EthernetHeader = struct {
        dst_mac: [6]u8, // Destination MAC address
        src_mac: [6]u8, // Source MAC address
        ethertype: u16, // EtherType (0x0800 for IPv4, 0x86DD for IPv6)

        fn write(self: *const EthernetHeader, writer: anytype) !void {
            try writer.writeAll(&self.dst_mac);
            try writer.writeAll(&self.src_mac);
            try writer.writeInt(u16, self.ethertype, .big);
        }
    };

    /// IPv4 header (20 bytes minimum, without options)
    const IPv4Header = struct {
        version_ihl: u8, // Version (4 bits) + IHL (4 bits)
        dscp_ecn: u8, // DSCP (6 bits) + ECN (2 bits)
        total_length: u16, // Total length
        identification: u16, // Identification
        flags_fragment: u16, // Flags (3 bits) + Fragment offset (13 bits)
        ttl: u8, // Time to live
        protocol: u8, // Protocol (17=UDP)
        checksum: u16, // Header checksum
        src_ip: [4]u8, // Source IP address
        dst_ip: [4]u8, // Destination IP address

        fn write(self: *const IPv4Header, writer: anytype) !void {
            try writer.writeByte(self.version_ihl);
            try writer.writeByte(self.dscp_ecn);
            try writer.writeInt(u16, self.total_length, .big);
            try writer.writeInt(u16, self.identification, .big);
            try writer.writeInt(u16, self.flags_fragment, .big);
            try writer.writeByte(self.ttl);
            try writer.writeByte(self.protocol);
            try writer.writeInt(u16, self.checksum, .big);
            try writer.writeAll(&self.src_ip);
            try writer.writeAll(&self.dst_ip);
        }
    };

    /// IPv6 header (40 bytes, fixed size)
    const IPv6Header = struct {
        version_tc_fl: u32, // Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
        payload_length: u16, // Payload length (UDP header + data)
        next_header: u8, // Next header (17=UDP)
        hop_limit: u8, // Hop limit
        src_ip: [16]u8, // Source IP address
        dst_ip: [16]u8, // Destination IP address

        fn write(self: *const IPv6Header, writer: anytype) !void {
            try writer.writeInt(u32, self.version_tc_fl, .big);
            try writer.writeInt(u16, self.payload_length, .big);
            try writer.writeByte(self.next_header);
            try writer.writeByte(self.hop_limit);
            try writer.writeAll(&self.src_ip);
            try writer.writeAll(&self.dst_ip);
        }
    };

    /// UDP header (8 bytes)
    const UdpHeader = struct {
        src_port: u16, // Source port
        dst_port: u16, // Destination port
        length: u16, // Length (header + data)
        checksum: u16, // Checksum

        fn write(self: *const UdpHeader, writer: anytype) !void {
            try writer.writeInt(u16, self.src_port, .big);
            try writer.writeInt(u16, self.dst_port, .big);
            try writer.writeInt(u16, self.length, .big);
            try writer.writeInt(u16, self.checksum, .big);
        }
    };

    /// Initialize PCAP writer and write global header
    pub fn init(file_path: []const u8) !PcapWriter {
        const file = try std.fs.cwd().createFile(file_path, .{});
        errdefer file.close();

        var writer = PcapWriter{
            .file = file,
            .mutex = .{},
            .packets_written = 0,
        };

        // Write global header
        try writer.writeGlobalHeader();

        return writer;
    }

    /// Close the PCAP file
    pub fn deinit(self: *PcapWriter) void {
        self.file.close();
    }

    /// Write PCAP global header
    fn writeGlobalHeader(self: *PcapWriter) !void {
        const writer = self.file.writer();

        // Write each field manually to avoid struct padding issues
        try writer.writeInt(u32, PCAP_MAGIC, .little);
        try writer.writeInt(u16, VERSION_MAJOR, .little);
        try writer.writeInt(u16, VERSION_MINOR, .little);
        try writer.writeInt(i32, 0, .little); // thiszone
        try writer.writeInt(u32, 0, .little); // sigfigs
        try writer.writeInt(u32, SNAPLEN, .little);
        try writer.writeInt(u32, LINKTYPE_ETHERNET, .little);
    }

    /// Write a UDP packet (containing GTP-U) to the PCAP file
    /// Automatically encapsulates in Ethernet/IP/UDP layers
    pub fn writeUdpPacket(
        self: *PcapWriter,
        timestamp_ns: i128,
        src_addr: std.net.Address,
        dst_addr: std.net.Address,
        payload: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Convert nanosecond timestamp to seconds/microseconds
        const ts_sec: u32 = @intCast(@divFloor(timestamp_ns, std.time.ns_per_s));
        const ts_usec: u32 = @intCast(@divFloor(@mod(timestamp_ns, std.time.ns_per_s), std.time.ns_per_us));

        // Prepare headers based on IP version
        if (src_addr.any.family == std.posix.AF.INET and dst_addr.any.family == std.posix.AF.INET) {
            try self.writeIPv4Packet(ts_sec, ts_usec, src_addr, dst_addr, payload);
        } else if (src_addr.any.family == std.posix.AF.INET6 and dst_addr.any.family == std.posix.AF.INET6) {
            try self.writeIPv6Packet(ts_sec, ts_usec, src_addr, dst_addr, payload);
        } else {
            // Mixed address families not supported
            return error.UnsupportedAddressFamily;
        }

        self.packets_written += 1;
    }

    /// Write an IPv4 packet to PCAP
    fn writeIPv4Packet(
        self: *PcapWriter,
        ts_sec: u32,
        ts_usec: u32,
        src_addr: std.net.Address,
        dst_addr: std.net.Address,
        payload: []const u8,
    ) !void {
        // Calculate packet sizes (wire format, not struct sizes)
        const eth_size: u32 = 14; // Ethernet: 6 + 6 + 2
        const ip_size: u32 = 20; // IPv4 header without options
        const udp_size: u32 = 8; // UDP header
        const total_size = eth_size + ip_size + udp_size + payload.len;

        // Write PCAP packet header (manually to avoid padding)
        const writer = self.file.writer();
        try writer.writeInt(u32, ts_sec, .little);
        try writer.writeInt(u32, ts_usec, .little);
        try writer.writeInt(u32, @intCast(total_size), .little); // incl_len
        try writer.writeInt(u32, @intCast(total_size), .little); // orig_len

        // Write Ethernet header (dummy MAC addresses)
        const eth_header = EthernetHeader{
            .dst_mac = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .src_mac = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 },
            .ethertype = 0x0800, // IPv4
        };
        try eth_header.write(self.file.writer());

        // Extract IP addresses and ports
        const src_ip = src_addr.in.sa.addr;
        const dst_ip = dst_addr.in.sa.addr;
        const src_port = src_addr.getPort();
        const dst_port = dst_addr.getPort();

        // Write IPv4 header
        const ip_total_length: u16 = @intCast(ip_size + udp_size + payload.len);
        var ip_header = IPv4Header{
            .version_ihl = 0x45, // Version 4, IHL 5 (20 bytes)
            .dscp_ecn = 0,
            .total_length = ip_total_length,
            .identification = 0,
            .flags_fragment = 0,
            .ttl = 64,
            .protocol = 17, // UDP
            .checksum = 0, // Will calculate
            .src_ip = @bitCast(src_ip),
            .dst_ip = @bitCast(dst_ip),
        };
        ip_header.checksum = calculateIPv4Checksum(&ip_header);
        try ip_header.write(self.file.writer());

        // Write UDP header
        const udp_length: u16 = @intCast(udp_size + payload.len);
        const udp_header = UdpHeader{
            .src_port = src_port,
            .dst_port = dst_port,
            .length = udp_length,
            .checksum = 0, // Optional for IPv4
        };
        try udp_header.write(self.file.writer());

        // Write payload (GTP-U packet)
        try self.file.writeAll(payload);
    }

    /// Write an IPv6 packet to PCAP
    fn writeIPv6Packet(
        self: *PcapWriter,
        ts_sec: u32,
        ts_usec: u32,
        src_addr: std.net.Address,
        dst_addr: std.net.Address,
        payload: []const u8,
    ) !void {
        // Calculate packet sizes (wire format)
        const eth_size: u32 = 14; // Ethernet: 6 + 6 + 2
        const ip_size: u32 = 40; // IPv6 header (fixed size)
        const udp_size: u32 = 8; // UDP header
        const total_size = eth_size + ip_size + udp_size + payload.len;

        // Write PCAP packet header
        const writer = self.file.writer();
        try writer.writeInt(u32, ts_sec, .little);
        try writer.writeInt(u32, ts_usec, .little);
        try writer.writeInt(u32, @intCast(total_size), .little); // incl_len
        try writer.writeInt(u32, @intCast(total_size), .little); // orig_len

        // Write Ethernet header (dummy MAC addresses)
        const eth_header = EthernetHeader{
            .dst_mac = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .src_mac = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 },
            .ethertype = 0x86DD, // IPv6
        };
        try eth_header.write(self.file.writer());

        // Extract IPv6 addresses and ports
        const src_ip = src_addr.in6.sa.addr;
        const dst_ip = dst_addr.in6.sa.addr;
        const src_port = src_addr.getPort();
        const dst_port = dst_addr.getPort();

        // Write IPv6 header
        const payload_length: u16 = @intCast(udp_size + payload.len);
        const ipv6_header = IPv6Header{
            .version_tc_fl = 0x60000000, // Version 6, Traffic Class 0, Flow Label 0
            .payload_length = payload_length,
            .next_header = 17, // UDP
            .hop_limit = 64,
            .src_ip = src_ip,
            .dst_ip = dst_ip,
        };
        try ipv6_header.write(self.file.writer());

        // Write UDP header
        const udp_length: u16 = @intCast(udp_size + payload.len);

        // Calculate UDP checksum for IPv6 (mandatory)
        const udp_checksum = calculateUDPv6Checksum(&ipv6_header, src_port, dst_port, udp_length, payload);

        const udp_header = UdpHeader{
            .src_port = src_port,
            .dst_port = dst_port,
            .length = udp_length,
            .checksum = udp_checksum,
        };
        try udp_header.write(self.file.writer());

        // Write payload (GTP-U packet)
        try self.file.writeAll(payload);
    }

    /// Calculate UDP checksum for IPv6 (mandatory)
    fn calculateUDPv6Checksum(
        ipv6_header: *const IPv6Header,
        src_port: u16,
        dst_port: u16,
        udp_length: u16,
        payload: []const u8,
    ) u16 {
        var sum: u32 = 0;

        // IPv6 pseudo-header: source address (16 bytes)
        var i: usize = 0;
        while (i < ipv6_header.src_ip.len) : (i += 2) {
            const word: u16 = (@as(u16, ipv6_header.src_ip[i]) << 8) | @as(u16, ipv6_header.src_ip[i + 1]);
            sum += word;
        }

        // IPv6 pseudo-header: destination address (16 bytes)
        i = 0;
        while (i < ipv6_header.dst_ip.len) : (i += 2) {
            const word: u16 = (@as(u16, ipv6_header.dst_ip[i]) << 8) | @as(u16, ipv6_header.dst_ip[i + 1]);
            sum += word;
        }

        // IPv6 pseudo-header: Upper-layer packet length (32-bit, big-endian)
        // Split into two 16-bit words: upper 16 bits (0) and lower 16 bits (udp_length)
        sum += 0; // Upper 16 bits
        sum += udp_length; // Lower 16 bits

        // IPv6 pseudo-header: Zero (24 bits) + Next Header (8 bits)
        // This forms a 32-bit word: 0x00000011 for UDP (0x11 = 17)
        sum += 0; // First 16 bits of zeros
        sum += 17; // Last 8 bits of zeros + Next Header (UDP = 17)

        // UDP header
        sum += src_port;
        sum += dst_port;
        sum += udp_length;
        // checksum field is 0 during calculation

        // UDP payload
        i = 0;
        while (i < payload.len) : (i += 2) {
            if (i + 1 < payload.len) {
                const word: u16 = (@as(u16, payload[i]) << 8) | @as(u16, payload[i + 1]);
                sum += word;
            } else {
                // Odd number of bytes, pad with 0
                const word: u16 = @as(u16, payload[i]) << 8;
                sum += word;
            }
        }

        // Add carry bits
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        return @intCast(~sum & 0xFFFF);
    }

    /// Calculate IPv4 header checksum
    fn calculateIPv4Checksum(header: *IPv4Header) u16 {
        var sum: u32 = 0;

        // Create a temporary buffer to serialize the header
        var buf: [20]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        header.write(fbs.writer()) catch unreachable; // Should never fail for fixed buffer

        // Sum all 16-bit words
        var i: usize = 0;
        while (i < buf.len) : (i += 2) {
            const word: u16 = (@as(u16, buf[i]) << 8) | @as(u16, buf[i + 1]);
            sum += word;
        }

        // Add carry bits
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement (return in big-endian)
        return @intCast(~sum & 0xFFFF);
    }

    /// Get the number of packets written
    pub fn getPacketCount(self: *const PcapWriter) u64 {
        return self.packets_written;
    }
};

/// PCAP capture helper for mock applications
pub const PcapCapture = struct {
    writer: ?*PcapWriter,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, pcap_file: ?[]const u8) !PcapCapture {
        var writer_ptr: ?*PcapWriter = null;

        if (pcap_file) |path| {
            const writer = try allocator.create(PcapWriter);
            errdefer allocator.destroy(writer);

            writer.* = try PcapWriter.init(path);
            writer_ptr = writer;

            std.debug.print("PCAP capture enabled: {s}\n", .{path});
        }

        return PcapCapture{
            .writer = writer_ptr,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PcapCapture) void {
        if (self.writer) |writer| {
            std.debug.print("PCAP capture: {} packets written\n", .{writer.getPacketCount()});
            writer.deinit();
            self.allocator.destroy(writer);
        }
    }

    /// Capture a UDP packet if PCAP is enabled
    pub fn capturePacket(
        self: *PcapCapture,
        src_addr: std.net.Address,
        dst_addr: std.net.Address,
        payload: []const u8,
    ) void {
        if (self.writer) |writer| {
            const timestamp = std.time.nanoTimestamp();
            writer.writeUdpPacket(timestamp, src_addr, dst_addr, payload) catch |err| {
                std.debug.print("PCAP write error: {}\n", .{err});
            };
        }
    }
};

// Tests
test "PCAP global header" {
    const testing = std.testing;

    // Create temporary file
    var tmp_dir = testing.tmpDir(.{});
    var dir = tmp_dir.dir;
    defer tmp_dir.cleanup();

    const file = try dir.createFile("test.pcap", .{ .read = true });
    defer file.close();

    // Write global header
    var writer = PcapWriter{
        .file = file,
        .mutex = .{},
        .packets_written = 0,
    };
    try writer.writeGlobalHeader();

    // Read and verify (should be exactly 24 bytes)
    try file.seekTo(0);
    var buffer: [24]u8 = undefined;
    const bytes_read = try file.readAll(&buffer);
    try testing.expectEqual(@as(usize, 24), bytes_read);

    // Verify magic number (first 4 bytes, little-endian)
    const magic = std.mem.readInt(u32, buffer[0..4], .little);
    try testing.expectEqual(PcapWriter.PCAP_MAGIC, magic);

    // Verify version
    const ver_major = std.mem.readInt(u16, buffer[4..6], .little);
    const ver_minor = std.mem.readInt(u16, buffer[6..8], .little);
    try testing.expectEqual(PcapWriter.VERSION_MAJOR, ver_major);
    try testing.expectEqual(PcapWriter.VERSION_MINOR, ver_minor);
}

test "PCAP IPv4 packet write" {
    const testing = std.testing;

    // Create temporary PCAP file
    var tmp_dir = testing.tmpDir(.{});
    var dir = tmp_dir.dir;
    defer tmp_dir.cleanup();

    const file_path = "test_packet.pcap";
    {
        var writer = try PcapWriter.init(file_path);
        defer writer.deinit();
        defer dir.deleteFile(file_path) catch {};

        const src = try std.net.Address.parseIp("192.168.1.1", 2152);
        const dst = try std.net.Address.parseIp("192.168.1.2", 2152);
        const payload = "Test GTP-U payload";

        try writer.writeUdpPacket(std.time.nanoTimestamp(), src, dst, payload);
        try testing.expectEqual(@as(u64, 1), writer.getPacketCount());
    }
}

test "PCAP IPv6 packet write" {
    const testing = std.testing;

    // Create temporary PCAP file
    var tmp_dir = testing.tmpDir(.{});
    var dir = tmp_dir.dir;
    defer tmp_dir.cleanup();

    const file_path = "test_ipv6_packet.pcap";
    {
        var writer = try PcapWriter.init(file_path);
        defer writer.deinit();
        defer dir.deleteFile(file_path) catch {};

        const src = try std.net.Address.parseIp6("2001:db8::1", 2152);
        const dst = try std.net.Address.parseIp6("2001:db8::2", 2152);
        const payload = "Test GTP-U IPv6 payload";

        try writer.writeUdpPacket(std.time.nanoTimestamp(), src, dst, payload);
        try testing.expectEqual(@as(u64, 1), writer.getPacketCount());
    }
}

test "PCAP mixed IPv4 and IPv6 packets" {
    const testing = std.testing;

    // Create temporary PCAP file
    var tmp_dir = testing.tmpDir(.{});
    var dir = tmp_dir.dir;
    defer tmp_dir.cleanup();

    const file_path = "test_mixed_packets.pcap";
    {
        var writer = try PcapWriter.init(file_path);
        defer writer.deinit();
        defer dir.deleteFile(file_path) catch {};

        // Write IPv4 packet
        const src_v4 = try std.net.Address.parseIp("192.168.1.1", 2152);
        const dst_v4 = try std.net.Address.parseIp("192.168.1.2", 2152);
        try writer.writeUdpPacket(std.time.nanoTimestamp(), src_v4, dst_v4, "IPv4 packet");

        // Write IPv6 packet
        const src_v6 = try std.net.Address.parseIp6("2001:db8::1", 2152);
        const dst_v6 = try std.net.Address.parseIp6("2001:db8::2", 2152);
        try writer.writeUdpPacket(std.time.nanoTimestamp(), src_v6, dst_v6, "IPv6 packet");

        try testing.expectEqual(@as(u64, 2), writer.getPacketCount());
    }
}
