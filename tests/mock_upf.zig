// Mock UPF (User Plane Function) for End-to-End Testing
// Simulates realistic 5G traffic scenarios

const std = @import("std");
const gtpu = @import("gtpu");

const MockUPF = struct {
    allocator: std.mem.Allocator,
    tunnel_mgr: gtpu.TunnelManager,
    session_mgr: gtpu.SessionManager,
    path_mgr: gtpu.PathManager,
    qos_mgr: gtpu.qos.QosFlowManager,
    packet_pool: gtpu.pool.PacketBufferPool,
    pcap_capture: gtpu.pcap.PcapCapture,

    listen_address: std.net.Address,
    socket: std.posix.socket_t,

    stats: Stats,
    running: std.atomic.Value(bool),

    const Stats = struct {
        packets_received: std.atomic.Value(u64),
        packets_sent: std.atomic.Value(u64),
        bytes_received: std.atomic.Value(u64),
        bytes_sent: std.atomic.Value(u64),
        echo_requests: std.atomic.Value(u64),
        echo_responses: std.atomic.Value(u64),
        g_pdus: std.atomic.Value(u64),
        errors: std.atomic.Value(u64),

        pub fn init() Stats {
            return .{
                .packets_received = std.atomic.Value(u64).init(0),
                .packets_sent = std.atomic.Value(u64).init(0),
                .bytes_received = std.atomic.Value(u64).init(0),
                .bytes_sent = std.atomic.Value(u64).init(0),
                .echo_requests = std.atomic.Value(u64).init(0),
                .echo_responses = std.atomic.Value(u64).init(0),
                .g_pdus = std.atomic.Value(u64).init(0),
                .errors = std.atomic.Value(u64).init(0),
            };
        }

        pub fn print(self: Stats) void {
            std.debug.print("\n=== Mock UPF Statistics ===\n", .{});
            std.debug.print("  Packets RX: {}\n", .{self.packets_received.load(.monotonic)});
            std.debug.print("  Packets TX: {}\n", .{self.packets_sent.load(.monotonic)});
            std.debug.print("  Bytes RX:   {}\n", .{self.bytes_received.load(.monotonic)});
            std.debug.print("  Bytes TX:   {}\n", .{self.bytes_sent.load(.monotonic)});
            std.debug.print("  Echo Req:   {}\n", .{self.echo_requests.load(.monotonic)});
            std.debug.print("  Echo Resp:  {}\n", .{self.echo_responses.load(.monotonic)});
            std.debug.print("  G-PDUs:     {}\n", .{self.g_pdus.load(.monotonic)});
            std.debug.print("  Errors:     {}\n", .{self.errors.load(.monotonic)});
        }
    };

    pub fn init(allocator: std.mem.Allocator, listen_addr: []const u8, port: u16, pcap_file: ?[]const u8) !MockUPF {
        const address = try std.net.Address.parseIp(listen_addr, port);

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

        var pcap_capture = try gtpu.pcap.PcapCapture.init(allocator, pcap_file);
        errdefer pcap_capture.deinit();

        return .{
            .allocator = allocator,
            .tunnel_mgr = tunnel_mgr,
            .session_mgr = undefined, // Caller must call initSessionManager()
            .path_mgr = path_mgr,
            .qos_mgr = qos_mgr,
            .packet_pool = packet_pool,
            .pcap_capture = pcap_capture,
            .listen_address = address,
            .socket = socket,
            .stats = Stats.init(),
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn initSessionManager(self: *MockUPF) void {
        self.session_mgr = gtpu.SessionManager.init(self.allocator, &self.tunnel_mgr);
    }

    pub fn deinit(self: *MockUPF) void {
        self.pcap_capture.deinit();
        std.posix.close(self.socket);
        self.packet_pool.deinit();
        self.qos_mgr.deinit();
        self.path_mgr.deinit();
        self.session_mgr.deinit();
        self.tunnel_mgr.deinit();
    }

    pub fn start(self: *MockUPF) !void {
        self.running.store(true, .monotonic);
        std.debug.print("Mock UPF listening on {}:{}\n", .{ self.listen_address.in.sa.addr, self.listen_address.getPort() });

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

            // Capture received packet to PCAP
            const src_address = std.net.Address.initPosix(@alignCast(&src_addr));
            self.pcap_capture.capturePacket(src_address, self.listen_address, recv_buffer[0..bytes_received]);

            // Process packet
            self.processPacket(recv_buffer[0..bytes_received], src_addr) catch |err| {
                std.debug.print("Error processing packet: {}\n", .{err});
                _ = self.stats.errors.fetchAdd(1, .monotonic);
            };
        }
    }

    pub fn stop(self: *MockUPF) void {
        self.running.store(false, .monotonic);
    }

    fn processPacket(self: *MockUPF, data: []const u8, src_addr: std.posix.sockaddr) !void {
        var stream = std.io.fixedBufferStream(data);
        var msg = try gtpu.GtpuMessage.decode(self.allocator, stream.reader());
        defer msg.deinit();

        switch (msg.header.message_type) {
            .echo_request => try self.handleEchoRequest(&msg, src_addr),
            .echo_response => try self.handleEchoResponse(&msg, src_addr),
            .g_pdu => try self.handleGpdu(&msg, src_addr),
            .end_marker => try self.handleEndMarker(&msg),
            .error_indication => try self.handleErrorIndication(&msg),
            else => {
                std.debug.print("Unhandled message type: {}\n", .{msg.header.message_type});
            },
        }
    }

    fn handleEchoRequest(self: *MockUPF, msg: *gtpu.GtpuMessage, src_addr: std.posix.sockaddr) !void {
        _ = self.stats.echo_requests.fetchAdd(1, .monotonic);

        const sequence = msg.header.sequence_number orelse 0;
        std.debug.print("Received Echo Request (seq: {})\n", .{sequence});

        // Send Echo Response
        var response = try gtpu.GtpuMessage.createEchoResponse(self.allocator, sequence);
        defer response.deinit();

        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);

        try response.encode(buffer.writer(self.allocator));

        // Capture sent packet to PCAP
        const dst_address = std.net.Address.initPosix(@alignCast(&src_addr));
        self.pcap_capture.capturePacket(self.listen_address, dst_address, buffer.items);

        _ = try std.posix.sendto(self.socket, buffer.items, 0, &src_addr, @sizeOf(std.posix.sockaddr));

        _ = self.stats.packets_sent.fetchAdd(1, .monotonic);
        _ = self.stats.bytes_sent.fetchAdd(buffer.items.len, .monotonic);
        _ = self.stats.echo_responses.fetchAdd(1, .monotonic);

        std.debug.print("Sent Echo Response (seq: {})\n", .{sequence});
    }

    fn handleEchoResponse(self: *MockUPF, msg: *gtpu.GtpuMessage, src_addr: std.posix.sockaddr) !void {
        const sequence = msg.header.sequence_number orelse 0;
        std.debug.print("Received Echo Response (seq: {})\n", .{sequence});

        // Update path state with echo response - critical for RTT measurement and path health
        const peer_address = std.net.Address.initPosix(@alignCast(&src_addr));
        if (self.path_mgr.getPath(peer_address)) |path| {
            const current_time = std.time.nanoTimestamp();
            path.receiveEchoResponse(sequence, current_time) catch |err| {
                std.debug.print("Echo response error: {} (seq mismatch or no pending echo)\n", .{err});
            };
        }

        _ = self.stats.echo_responses.fetchAdd(1, .monotonic);
    }

    fn handleGpdu(self: *MockUPF, msg: *gtpu.GtpuMessage, src_addr: std.posix.sockaddr) !void {
        _ = src_addr;
        _ = self.stats.g_pdus.fetchAdd(1, .monotonic);

        std.debug.print("Received G-PDU (TEID: 0x{X:0>8}, {} bytes)\n", .{ msg.header.teid, msg.payload.len });

        // Find tunnel
        if (self.tunnel_mgr.getTunnel(msg.header.teid)) |tunnel| {
            tunnel.stats.recordRx(msg.payload.len);

            // Process extension headers (QoS flow handling)
            for (msg.extension_headers.items) |ext| {
                switch (ext) {
                    .pdu_session_container => |psc| {
                        std.debug.print("  QFI: {}, PDU Type: {}\n", .{ psc.qfi, psc.pdu_type });

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

    fn handleEndMarker(self: *MockUPF, msg: *gtpu.GtpuMessage) !void {
        _ = self;
        std.debug.print("Received End Marker (TEID: 0x{X:0>8})\n", .{msg.header.teid});
    }

    fn handleErrorIndication(self: *MockUPF, msg: *gtpu.GtpuMessage) !void {
        _ = self;
        std.debug.print("Received Error Indication (TEID: 0x{X:0>8})\n", .{msg.header.teid});
    }

    pub fn createTestSession(self: *MockUPF, session_id: u8, remote_addr: std.net.Address) !void {
        try self.session_mgr.createSession(
            session_id,
            .ipv4,
            "internet",
            self.listen_address,
            remote_addr,
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
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip program name

    const listen_addr = args.next() orelse "0.0.0.0";
    const port_str = args.next() orelse "2152";
    const port = try std.fmt.parseInt(u16, port_str, 10);

    const pcap_file = args.next(); // Optional PCAP file path

    std.debug.print("=== Mock UPF Starting ===\n", .{});

    var upf = try MockUPF.init(allocator, listen_addr, port, pcap_file);
    defer upf.deinit();

    // Initialize session manager (must be done after init returns)
    upf.initSessionManager();

    // Create a test session
    const remote_addr = try std.net.Address.parseIp("192.168.1.100", gtpu.protocol.GTPU_PORT);
    try upf.createTestSession(1, remote_addr);

    // Handle SIGINT for graceful shutdown
    const signal_handler = struct {
        var upf_ptr: ?*MockUPF = null;

        fn handle(sig: c_int) callconv(.c) void {
            _ = sig;
            std.debug.print("\n\nReceived Ctrl+C, shutting down gracefully...\n", .{});
            if (upf_ptr) |u| {
                u.stop();
            }
        }
    };

    signal_handler.upf_ptr = &upf;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = signal_handler.handle },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);

    // Start processing
    try upf.start();

    // Print stats on exit
    upf.stats.print();
}
