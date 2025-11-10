// Mock gNodeB (gNB) for End-to-End Testing
// Simulates realistic 5G RAN (Radio Access Network) behavior
// Generates uplink traffic and processes downlink traffic

const std = @import("std");
const gtpu = @import("gtpu");

const MockGNB = struct {
    allocator: std.mem.Allocator,
    tunnel_mgr: gtpu.TunnelManager,
    session_mgr: gtpu.SessionManager,
    path_mgr: gtpu.PathManager,
    qos_mgr: gtpu.qos.QosFlowManager,
    packet_pool: gtpu.pool.PacketBufferPool,

    listen_address: std.net.Address,
    upf_address: std.net.Address,
    socket: std.posix.socket_t,

    stats: Stats,
    running: std.atomic.Value(bool),
    traffic_running: std.atomic.Value(bool),

    const Stats = struct {
        packets_received: std.atomic.Value(u64),
        packets_sent: std.atomic.Value(u64),
        bytes_received: std.atomic.Value(u64),
        bytes_sent: std.atomic.Value(u64),
        echo_requests: std.atomic.Value(u64),
        echo_responses: std.atomic.Value(u64),
        uplink_g_pdus: std.atomic.Value(u64),
        downlink_g_pdus: std.atomic.Value(u64),
        errors: std.atomic.Value(u64),

        pub fn init() Stats {
            return .{
                .packets_received = std.atomic.Value(u64).init(0),
                .packets_sent = std.atomic.Value(u64).init(0),
                .bytes_received = std.atomic.Value(u64).init(0),
                .bytes_sent = std.atomic.Value(u64).init(0),
                .echo_requests = std.atomic.Value(u64).init(0),
                .echo_responses = std.atomic.Value(u64).init(0),
                .uplink_g_pdus = std.atomic.Value(u64).init(0),
                .downlink_g_pdus = std.atomic.Value(u64).init(0),
                .errors = std.atomic.Value(u64).init(0),
            };
        }

        pub fn print(self: Stats) void {
            std.debug.print("\n=== Mock gNB Statistics ===\n", .{});
            std.debug.print("  Packets RX:    {}\n", .{self.packets_received.load(.monotonic)});
            std.debug.print("  Packets TX:    {}\n", .{self.packets_sent.load(.monotonic)});
            std.debug.print("  Bytes RX:      {}\n", .{self.bytes_received.load(.monotonic)});
            std.debug.print("  Bytes TX:      {}\n", .{self.bytes_sent.load(.monotonic)});
            std.debug.print("  Echo Req:      {}\n", .{self.echo_requests.load(.monotonic)});
            std.debug.print("  Echo Resp:     {}\n", .{self.echo_responses.load(.monotonic)});
            std.debug.print("  Uplink G-PDUs: {}\n", .{self.uplink_g_pdus.load(.monotonic)});
            std.debug.print("  Downlink G-PDUs: {}\n", .{self.downlink_g_pdus.load(.monotonic)});
            std.debug.print("  Errors:        {}\n", .{self.errors.load(.monotonic)});
        }
    };

    pub fn init(allocator: std.mem.Allocator, listen_addr: []const u8, port: u16, upf_addr: []const u8, upf_port: u16) !MockGNB {
        const address = try std.net.Address.parseIp(listen_addr, port);
        const upf_address = try std.net.Address.parseIp(upf_addr, upf_port);

        const socket = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(socket);

        try std.posix.bind(socket, &address.any, address.getOsSockLen());

        // Set receive timeout to allow periodic checking of running flag
        const timeout = std.posix.timeval{
            .sec = 1,
            .usec = 0,
        };
        try std.posix.setsockopt(
            socket,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );

        var tunnel_mgr = gtpu.TunnelManager.init(allocator);
        errdefer tunnel_mgr.deinit();

        const path_config = gtpu.path.PathConfig{
            .echo_interval_ms = 60000,
            .echo_timeout_ms = 5000,
            .max_echo_failures = 3,
        };
        var path_mgr = gtpu.PathManager.init(allocator, path_config);
        errdefer path_mgr.deinit();

        var qos_mgr = gtpu.qos.QosFlowManager.init(allocator);
        errdefer qos_mgr.deinit();

        var packet_pool = try gtpu.pool.PacketBufferPool.init(allocator, 1000, 2048);
        errdefer packet_pool.deinit();

        return .{
            .allocator = allocator,
            .tunnel_mgr = tunnel_mgr,
            .session_mgr = undefined, // Caller must call initSessionManager()
            .path_mgr = path_mgr,
            .qos_mgr = qos_mgr,
            .packet_pool = packet_pool,
            .listen_address = address,
            .upf_address = upf_address,
            .socket = socket,
            .stats = Stats.init(),
            .running = std.atomic.Value(bool).init(false),
            .traffic_running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn initSessionManager(self: *MockGNB) void {
        self.session_mgr = gtpu.SessionManager.init(self.allocator, &self.tunnel_mgr);
    }

    pub fn deinit(self: *MockGNB) void {
        std.posix.close(self.socket);
        self.packet_pool.deinit();
        self.qos_mgr.deinit();
        self.path_mgr.deinit();
        self.session_mgr.deinit();
        self.tunnel_mgr.deinit();
    }

    pub fn start(self: *MockGNB) !void {
        self.running.store(true, .monotonic);
        std.debug.print("Mock gNB listening on {}:{}\n", .{ self.listen_address.in.sa.addr, self.listen_address.getPort() });
        std.debug.print("Mock gNB connected to UPF at {}:{}\n", .{ self.upf_address.in.sa.addr, self.upf_address.getPort() });

        var recv_buffer: [2048]u8 = undefined;

        while (self.running.load(.monotonic)) {
            var src_addr: std.posix.sockaddr = undefined;
            var src_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

            const bytes_received = std.posix.recvfrom(
                self.socket,
                &recv_buffer,
                0,
                &src_addr,
                &src_addr_len,
            ) catch |err| {
                // Timeout is expected, just continue to check running flag
                if (err == error.WouldBlock) {
                    continue;
                }
                std.debug.print("Error receiving: {}\n", .{err});
                _ = self.stats.errors.fetchAdd(1, .monotonic);
                continue;
            };

            _ = self.stats.packets_received.fetchAdd(1, .monotonic);
            _ = self.stats.bytes_received.fetchAdd(bytes_received, .monotonic);

            // Process packet
            self.processPacket(recv_buffer[0..bytes_received], src_addr) catch |err| {
                std.debug.print("Error processing packet: {}\n", .{err});
                _ = self.stats.errors.fetchAdd(1, .monotonic);
            };
        }
    }

    pub fn stop(self: *MockGNB) void {
        self.running.store(false, .monotonic);
        self.traffic_running.store(false, .monotonic);
    }

    fn processPacket(self: *MockGNB, data: []const u8, src_addr: std.posix.sockaddr) !void {
        var stream = std.io.fixedBufferStream(data);
        var msg = try gtpu.GtpuMessage.decode(self.allocator, stream.reader());
        defer msg.deinit();

        switch (msg.header.message_type) {
            .echo_request => try self.handleEchoRequest(&msg, src_addr),
            .echo_response => try self.handleEchoResponse(&msg),
            .g_pdu => try self.handleDownlinkGpdu(&msg, src_addr),
            .end_marker => try self.handleEndMarker(&msg),
            .error_indication => try self.handleErrorIndication(&msg),
            else => {
                std.debug.print("Unhandled message type: {}\n", .{msg.header.message_type});
            },
        }
    }

    fn handleEchoRequest(self: *MockGNB, msg: *gtpu.GtpuMessage, src_addr: std.posix.sockaddr) !void {
        _ = self.stats.echo_requests.fetchAdd(1, .monotonic);

        const sequence = msg.header.sequence_number orelse 0;
        std.debug.print("Received Echo Request (seq: {})\n", .{sequence});

        // Send Echo Response
        var response = try gtpu.GtpuMessage.createEchoResponse(self.allocator, sequence);
        defer response.deinit();

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try response.encode(buffer.writer());

        _ = try std.posix.sendto(self.socket, buffer.items, 0, &src_addr, @sizeOf(std.posix.sockaddr));

        _ = self.stats.packets_sent.fetchAdd(1, .monotonic);
        _ = self.stats.bytes_sent.fetchAdd(buffer.items.len, .monotonic);
        _ = self.stats.echo_responses.fetchAdd(1, .monotonic);

        std.debug.print("Sent Echo Response (seq: {})\n", .{sequence});
    }

    fn handleEchoResponse(self: *MockGNB, msg: *gtpu.GtpuMessage) !void {
        _ = self;
        const sequence = msg.header.sequence_number orelse 0;
        std.debug.print("Received Echo Response (seq: {})\n", .{sequence});
    }

    fn handleDownlinkGpdu(self: *MockGNB, msg: *gtpu.GtpuMessage, src_addr: std.posix.sockaddr) !void {
        _ = src_addr;
        _ = self.stats.downlink_g_pdus.fetchAdd(1, .monotonic);

        std.debug.print("Received DL G-PDU (TEID: 0x{X:0>8}, {} bytes)\n", .{ msg.header.teid, msg.payload.len });

        // Find tunnel
        if (self.tunnel_mgr.getTunnel(msg.header.teid)) |tunnel| {
            tunnel.stats.recordRx(msg.payload.len);

            // Process extension headers (QoS flow handling)
            for (msg.extension_headers.items) |ext| {
                switch (ext) {
                    .pdu_session_container => |psc| {
                        std.debug.print("  QFI: {}, PDU Type: {} (DL)\n", .{ psc.qfi, psc.pdu_type });

                        // Update QoS flow stats
                        if (self.qos_mgr.getFlow(psc.qfi)) |flow| {
                            flow.stats.recordPacket(msg.payload.len, 1000, false); // 1ms delay
                        }
                    },
                    else => {},
                }
            }
        } else {
            std.debug.print("  Warning: Unknown TEID\n", .{});
        }
    }

    fn handleEndMarker(self: *MockGNB, msg: *gtpu.GtpuMessage) !void {
        _ = self;
        std.debug.print("Received End Marker (TEID: 0x{X:0>8})\n", .{msg.header.teid});
    }

    fn handleErrorIndication(self: *MockGNB, msg: *gtpu.GtpuMessage) !void {
        _ = self;
        std.debug.print("Received Error Indication (TEID: 0x{X:0>8})\n", .{msg.header.teid});
    }

    pub fn createTestSession(self: *MockGNB, session_id: u8) !void {
        try self.session_mgr.createSession(
            session_id,
            .ipv4,
            "internet",
            self.listen_address,
            self.upf_address,
        );

        if (self.session_mgr.getSession(session_id)) |session| {
            // Add default QoS flow
            const qos_params = gtpu.qos.QosFlowParams{
                .qfi = 9,
                .fiveqi = .default_bearer,
                .arp = gtpu.qos.AllocationRetentionPriority.init(5),
            };

            try session.addQosFlow(qos_params);
            try self.qos_mgr.createFlow(qos_params);
            try session.activate();

            std.debug.print("Created test session {} with TEID UL: 0x{X:0>8}, DL: 0x{X:0>8}\n", .{
                session_id,
                session.uplink_tunnel.?,
                session.downlink_tunnel.?,
            });
        }
    }

    pub fn sendEchoRequest(self: *MockGNB, sequence: u16) !void {
        var msg = try gtpu.GtpuMessage.createEchoRequest(self.allocator, sequence);
        defer msg.deinit();

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try msg.encode(buffer.writer());

        _ = try std.posix.sendto(
            self.socket,
            buffer.items,
            0,
            &self.upf_address.any,
            self.upf_address.getOsSockLen(),
        );

        _ = self.stats.packets_sent.fetchAdd(1, .monotonic);
        _ = self.stats.bytes_sent.fetchAdd(buffer.items.len, .monotonic);
        _ = self.stats.echo_requests.fetchAdd(1, .monotonic);

        std.debug.print("Sent Echo Request (seq: {})\n", .{sequence});
    }

    pub fn sendUplinkGpdu(self: *MockGNB, session_id: u8, payload: []const u8) !void {
        const session = self.session_mgr.getSession(session_id) orelse return error.SessionNotFound;
        const uplink_teid = session.uplink_tunnel orelse return error.NoUplinkTunnel;

        // Get tunnel
        const tunnel = self.tunnel_mgr.getTunnel(uplink_teid) orelse return error.TunnelNotFound;

        // Create PDU Session Container extension header for uplink
        const pdu_container = gtpu.extension.ExtensionHeader{
            .pdu_session_container = .{
                .pdu_type = 1, // 1 = Uplink
                .qfi = 9, // Default QoS Flow Identifier
                .ppi = 0,
                .rqi = false,
            },
        };

        // Create G-PDU message with extension headers
        var msg = gtpu.GtpuMessage.createGpdu(self.allocator, uplink_teid, payload);
        defer msg.deinit();

        // Add extension headers
        try msg.addExtensionHeader(pdu_container);

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try msg.encode(buffer.writer());

        _ = try std.posix.sendto(
            self.socket,
            buffer.items,
            0,
            &self.upf_address.any,
            self.upf_address.getOsSockLen(),
        );

        _ = self.stats.packets_sent.fetchAdd(1, .monotonic);
        _ = self.stats.bytes_sent.fetchAdd(buffer.items.len, .monotonic);
        _ = self.stats.uplink_g_pdus.fetchAdd(1, .monotonic);

        tunnel.stats.recordTx(payload.len);

        std.debug.print("Sent UL G-PDU (TEID: 0x{X:0>8}, {} bytes, QFI: 9)\n", .{ uplink_teid, payload.len });
    }

    pub fn startTrafficGeneration(self: *MockGNB, session_id: u8, interval_ms: u64, packet_size: usize) !void {
        self.traffic_running.store(true, .monotonic);

        // Spawn a thread for traffic generation
        const thread = try std.Thread.spawn(.{}, trafficGeneratorThread, .{ self, session_id, interval_ms, packet_size });
        thread.detach();

        std.debug.print("Started traffic generation: session={}, interval={}ms, size={} bytes\n", .{ session_id, interval_ms, packet_size });
    }

    fn trafficGeneratorThread(self: *MockGNB, session_id: u8, interval_ms: u64, packet_size: usize) void {
        var counter: u64 = 0;
        var payload_buf: [2048]u8 = undefined;

        while (self.traffic_running.load(.monotonic)) {
            // Generate test payload
            const payload = payload_buf[0..packet_size];
            for (payload, 0..) |*byte, i| {
                byte.* = @intCast((counter + i) % 256);
            }

            // Send uplink G-PDU
            self.sendUplinkGpdu(session_id, payload) catch |err| {
                std.debug.print("Error sending uplink G-PDU: {}\n", .{err});
                _ = self.stats.errors.fetchAdd(1, .monotonic);
            };

            counter += 1;

            // Sleep for the specified interval
            std.time.sleep(interval_ms * std.time.ns_per_ms);
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip program name

    const listen_addr = args.next() orelse "0.0.0.0";
    const port_str = args.next() orelse "2153";
    const port = try std.fmt.parseInt(u16, port_str, 10);

    const upf_addr = args.next() orelse "127.0.0.1";
    const upf_port_str = args.next() orelse "2152";
    const upf_port = try std.fmt.parseInt(u16, upf_port_str, 10);

    std.debug.print("=== Mock gNB Starting ===\n", .{});

    var gnb = try MockGNB.init(allocator, listen_addr, port, upf_addr, upf_port);
    defer gnb.deinit();

    // Initialize session manager (must be done after init returns)
    gnb.initSessionManager();

    // Create a test session
    try gnb.createTestSession(1);

    // Send initial Echo Request to establish path
    try gnb.sendEchoRequest(1);

    // Start traffic generation (1 packet per second, 1024 bytes)
    try gnb.startTrafficGeneration(1, 1000, 1024);

    // Handle SIGINT for graceful shutdown
    const signal_handler = struct {
        var gnb_ptr: ?*MockGNB = null;

        fn handle(sig: c_int) callconv(.C) void {
            _ = sig;
            std.debug.print("\n\nReceived Ctrl+C, shutting down gracefully...\n", .{});
            if (gnb_ptr) |g| {
                g.stop();
            }
        }
    };

    signal_handler.gnb_ptr = &gnb;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = signal_handler.handle },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);

    // Start processing
    try gnb.start();

    // Print stats on exit
    gnb.stats.print();
}
