// GTP-U Example Application
// Demonstrates basic GTP-U functionality

const std = @import("std");
const gtpu = @import("lib.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== GTP-U for 5G Networks ===\n", .{});
    std.debug.print("Version: {}\n\n", .{gtpu.version});

    // Initialize tunnel manager
    var tunnel_mgr = gtpu.TunnelManager.init(allocator);
    defer tunnel_mgr.deinit();

    // Initialize session manager
    var session_mgr = gtpu.SessionManager.init(allocator, &tunnel_mgr);
    defer session_mgr.deinit();

    // Initialize path manager
    const path_config = gtpu.path.PathConfig{
        .echo_interval_ms = 60000,
        .echo_timeout_ms = 5000,
        .max_echo_failures = 3,
    };
    var path_mgr = gtpu.PathManager.init(allocator, path_config);
    defer path_mgr.deinit();

    std.debug.print("Managers initialized successfully\n", .{});

    // Example: Create a PDU session
    const local_addr = try std.net.Address.parseIp("192.168.1.1", gtpu.protocol.GTPU_PORT);
    const remote_addr = try std.net.Address.parseIp("192.168.1.2", gtpu.protocol.GTPU_PORT);

    try session_mgr.createSession(1, .ipv4, "internet", local_addr, remote_addr);
    std.debug.print("Created PDU session 1 (IPv4, DNN: internet)\n", .{});

    if (session_mgr.getSession(1)) |session| {
        std.debug.print("  Uplink TEID: 0x{X:0>8}\n", .{session.uplink_tunnel.?});
        std.debug.print("  Downlink TEID: 0x{X:0>8}\n", .{session.downlink_tunnel.?});

        // Add QoS flow
        const qos_params = gtpu.qos.QosFlowParams{
            .qfi = 9,
            .fiveqi = .default_bearer,
            .arp = gtpu.qos.AllocationRetentionPriority.init(5),
            .packet_delay_budget = 100,
        };

        try session.addQosFlow(qos_params);
        std.debug.print("  Added QoS Flow: QFI={}, 5QI={s}\n", .{ qos_params.qfi, @tagName(qos_params.fiveqi) });

        // Activate session
        try session.activate();
        std.debug.print("  Session activated\n", .{});
    }

    std.debug.print("\nSession statistics:\n", .{});
    std.debug.print("  Total sessions: {}\n", .{session_mgr.getSessionCount()});
    std.debug.print("  Active sessions: {}\n", .{session_mgr.getActiveSessions()});
    std.debug.print("  Total tunnels: {}\n", .{tunnel_mgr.getTunnelCount()});
    std.debug.print("  Active tunnels: {}\n", .{tunnel_mgr.getActiveTunnels()});

    // Example: Create and encode a G-PDU message
    std.debug.print("\n=== G-PDU Example ===\n", .{});

    const payload = "Hello, 5G Core Network!";
    var gpdu = gtpu.GtpuMessage.createGpdu(allocator, 0x12345678, payload);
    defer gpdu.deinit();

    // Add PDU Session Container extension header
    const pdu_container = gtpu.extension.ExtensionHeader{
        .pdu_session_container = .{
            .pdu_type = 1, // UL
            .qfi = 9,
            .ppi = 0,
            .rqi = false,
        },
    };
    try gpdu.addExtensionHeader(pdu_container);

    std.debug.print("Created G-PDU:\n", .{});
    std.debug.print("  TEID: 0x{X:0>8}\n", .{gpdu.header.teid});
    std.debug.print("  Payload: {s}\n", .{payload});
    std.debug.print("  Extension Headers: {}\n", .{gpdu.extension_headers.items.len});

    // Encode the message
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try gpdu.encode(buffer.writer());
    std.debug.print("  Encoded size: {} bytes\n", .{buffer.items.len});

    // Example: Echo Request/Response
    std.debug.print("\n=== Echo Request/Response Example ===\n", .{});

    var echo_req = try gtpu.GtpuMessage.createEchoRequest(allocator, 42);
    defer echo_req.deinit();

    var echo_buffer = std.ArrayList(u8).init(allocator);
    defer echo_buffer.deinit();

    try echo_req.encode(echo_buffer.writer());
    std.debug.print("Echo Request (seq: 42) encoded: {} bytes\n", .{echo_buffer.items.len});

    // Decode the echo request
    var stream = std.io.fixedBufferStream(echo_buffer.items);
    var decoded_echo = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer decoded_echo.deinit();

    std.debug.print("Decoded message type: {s}\n", .{decoded_echo.header.message_type.toString()});
    std.debug.print("Decoded sequence: {}\n", .{decoded_echo.header.sequence_number.?});

    // Example: TEID generation
    std.debug.print("\n=== TEID Generation ===\n", .{});

    var teid_gen = try gtpu.utils.TeidGenerator.init();
    std.debug.print("Generated TEIDs:\n", .{});
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const teid = teid_gen.generate();
        std.debug.print("  TEID #{}: 0x{X:0>8}\n", .{ i + 1, teid });
    }

    // Example: Memory pool performance
    std.debug.print("\n=== Memory Pool Example ===\n", .{});

    var packet_pool = try gtpu.pool.PacketBufferPool.init(allocator, 100, 2048);
    defer packet_pool.deinit();

    std.debug.print("Packet buffer pool created:\n", .{});
    std.debug.print("  Capacity: {} buffers\n", .{packet_pool.available()});
    std.debug.print("  Buffer size: {} bytes\n", .{packet_pool.buffer_size});

    const buf1 = packet_pool.acquire();
    const buf2 = packet_pool.acquire();

    std.debug.print("  After acquiring 2 buffers: {} available\n", .{packet_pool.available()});

    if (buf1) |b1| packet_pool.release(b1);
    if (buf2) |b2| packet_pool.release(b2);

    std.debug.print("  After releasing: {} available\n", .{packet_pool.available()});

    std.debug.print("\n=== GTP-U Demo Complete ===\n", .{});
}
