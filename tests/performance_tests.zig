// Performance Tests and Benchmarks
// Tests for throughput, latency, and scalability

const std = @import("std");
const gtpu = @import("../src/lib.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== GTP-U Performance Benchmarks ===\n\n", .{});

    try benchmarkPacketEncodeDecode(allocator);
    try benchmarkTunnelOperations(allocator);
    try benchmarkMemoryPool(allocator);
    try benchmarkThroughput(allocator);
    try benchmarkConcurrentSessions(allocator);

    std.debug.print("\n=== All Benchmarks Complete ===\n", .{});
}

fn benchmarkPacketEncodeDecode(allocator: std.mem.Allocator) !void {
    std.debug.print("--- Packet Encode/Decode Benchmark ---\n", .{});

    const iterations = 10000;
    const payload = "Test payload for GTP-U performance measurement with realistic data size";

    var timer = try std.time.Timer.start();

    // Encode benchmark
    var encode_time: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var msg = gtpu.GtpuMessage.createGpdu(allocator, 0x12345678, payload);
        defer msg.deinit();

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        const start = timer.read();
        try msg.encode(buffer.writer());
        encode_time += timer.read() - start;
    }

    const avg_encode_ns = encode_time / iterations;
    std.debug.print("  Encode: {} iterations in {} ms\n", .{ iterations, encode_time / std.time.ns_per_ms });
    std.debug.print("  Average: {} ns per packet ({d:.2} µs)\n", .{ avg_encode_ns, @as(f64, @floatFromInt(avg_encode_ns)) / 1000.0 });

    // Decode benchmark
    var msg = gtpu.GtpuMessage.createGpdu(allocator, 0x12345678, payload);
    defer msg.deinit();

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try msg.encode(buffer.writer());

    var decode_time: u64 = 0;
    i = 0;
    while (i < iterations) : (i += 1) {
        var stream = std.io.fixedBufferStream(buffer.items);

        const start = timer.read();
        var decoded = try gtpu.GtpuMessage.decode(allocator, stream.reader());
        decode_time += timer.read() - start;
        decoded.deinit();
    }

    const avg_decode_ns = decode_time / iterations;
    std.debug.print("  Decode: {} iterations in {} ms\n", .{ iterations, decode_time / std.time.ns_per_ms });
    std.debug.print("  Average: {} ns per packet ({d:.2} µs)\n", .{ avg_decode_ns, @as(f64, @floatFromInt(avg_decode_ns)) / 1000.0 });

    const throughput = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(encode_time + decode_time)) / @as(f64, std.time.ns_per_s));
    std.debug.print("  Throughput: {d:.0} packets/sec\n\n", .{throughput});
}

fn benchmarkTunnelOperations(allocator: std.mem.Allocator) !void {
    std.debug.print("--- Tunnel Operations Benchmark ---\n", .{});

    var timer = try std.time.Timer.start();
    var tunnel_mgr = gtpu.TunnelManager.init(allocator);
    defer tunnel_mgr.deinit();

    const num_tunnels = 1000;

    // Tunnel creation
    const create_start = timer.read();
    var i: usize = 0;
    while (i < num_tunnels) : (i += 1) {
        const config = gtpu.tunnel.TunnelConfig{
            .local_teid = tunnel_mgr.allocateTeid(),
            .remote_teid = @intCast(i),
            .local_address = try std.net.Address.parseIp("192.168.1.1", 2152),
            .remote_address = try std.net.Address.parseIp("192.168.1.2", 2152),
        };
        _ = try tunnel_mgr.createTunnel(config);
    }
    const create_time = timer.read() - create_start;

    std.debug.print("  Created {} tunnels in {} ms\n", .{ num_tunnels, create_time / std.time.ns_per_ms });
    std.debug.print("  Average: {d:.2} µs per tunnel\n", .{@as(f64, @floatFromInt(create_time / num_tunnels)) / 1000.0});

    // Tunnel lookup
    const lookup_iterations = 100000;
    const lookup_start = timer.read();
    var j: usize = 0;
    while (j < lookup_iterations) : (j += 1) {
        const teid = 0x1000 + @as(u32, @intCast(j % num_tunnels));
        _ = tunnel_mgr.getTunnel(teid);
    }
    const lookup_time = timer.read() - lookup_start;

    std.debug.print("  Performed {} lookups in {} ms\n", .{ lookup_iterations, lookup_time / std.time.ns_per_ms });
    std.debug.print("  Average: {} ns per lookup\n\n", .{lookup_time / lookup_iterations});
}

fn benchmarkMemoryPool(allocator: std.mem.Allocator) !void {
    std.debug.print("--- Memory Pool Benchmark ---\n", .{});

    var timer = try std.time.Timer.start();

    const pool_size = 1000;
    const buffer_size = 2048;

    var pool = try gtpu.pool.PacketBufferPool.init(allocator, pool_size, buffer_size);
    defer pool.deinit();

    // Acquire/release benchmark
    const iterations = 100000;
    const start = timer.read();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const buf = pool.acquire();
        if (buf) |b| {
            b.setLength(1000);
            pool.release(b);
        }
    }

    const elapsed = timer.read() - start;

    std.debug.print("  Pool operations: {} iterations in {} ms\n", .{ iterations, elapsed / std.time.ns_per_ms });
    std.debug.print("  Average: {} ns per acquire/release cycle\n", .{elapsed / iterations});

    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / @as(f64, std.time.ns_per_s));
    std.debug.print("  Throughput: {d:.0} operations/sec\n\n", .{ops_per_sec});
}

fn benchmarkThroughput(allocator: std.mem.Allocator) !void {
    std.debug.print("--- Throughput Benchmark ---\n", .{});

    var timer = try std.time.Timer.start();

    const num_packets = 10000;
    const payload_size = 1400; // Typical MTU-sized payload

    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const start = timer.read();

    var i: usize = 0;
    var total_bytes: usize = 0;
    while (i < num_packets) : (i += 1) {
        var msg = gtpu.GtpuMessage.createGpdu(allocator, 0x12345678, payload);
        defer msg.deinit();

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        try msg.encode(buffer.writer());
        total_bytes += buffer.items.len;
    }

    const elapsed = timer.read() - start;
    const elapsed_sec = @as(f64, @floatFromInt(elapsed)) / @as(f64, std.time.ns_per_s);

    const packets_per_sec = @as(f64, @floatFromInt(num_packets)) / elapsed_sec;
    const mbps = (@as(f64, @floatFromInt(total_bytes)) * 8.0) / (elapsed_sec * 1_000_000.0);

    std.debug.print("  Processed {} packets ({d:.2} MB) in {} ms\n", .{
        num_packets,
        @as(f64, @floatFromInt(total_bytes)) / 1_000_000.0,
        elapsed / std.time.ns_per_ms,
    });
    std.debug.print("  Throughput: {d:.0} packets/sec\n", .{packets_per_sec});
    std.debug.print("  Bandwidth: {d:.2} Mbps\n", .{mbps});
    std.debug.print("  Latency: {d:.2} µs per packet\n\n", .{@as(f64, @floatFromInt(elapsed / num_packets)) / 1000.0});
}

fn benchmarkConcurrentSessions(allocator: std.mem.Allocator) !void {
    std.debug.print("--- Concurrent Sessions Benchmark ---\n", .{});

    var timer = try std.time.Timer.start();

    var tunnel_mgr = gtpu.TunnelManager.init(allocator);
    defer tunnel_mgr.deinit();

    var session_mgr = gtpu.SessionManager.init(allocator, &tunnel_mgr);
    defer session_mgr.deinit();

    const num_sessions = 1000;
    const local_addr = try std.net.Address.parseIp("192.168.1.1", 2152);
    const remote_addr = try std.net.Address.parseIp("192.168.1.2", 2152);

    // Create sessions
    const create_start = timer.read();
    var i: u8 = 0;
    while (i < num_sessions) : (i +%= 1) {
        try session_mgr.createSession(i, .ipv4, "internet", local_addr, remote_addr);

        if (session_mgr.getSession(i)) |session| {
            const qos_params = gtpu.qos.QosFlowParams{
                .qfi = 9,
                .fiveqi = .default_bearer,
                .arp = gtpu.qos.AllocationRetentionPriority.init(5),
            };
            try session.addQosFlow(qos_params);
            try session.activate();
        }
    }
    const create_time = timer.read() - create_start;

    std.debug.print("  Created {} sessions in {} ms\n", .{ num_sessions, create_time / std.time.ns_per_ms });
    std.debug.print("  Average: {d:.2} µs per session\n", .{@as(f64, @floatFromInt(create_time / num_sessions)) / 1000.0});
    std.debug.print("  Active sessions: {}\n", .{session_mgr.getActiveSessions()});
    std.debug.print("  Active tunnels: {}\n\n", .{tunnel_mgr.getActiveTunnels()});
}
