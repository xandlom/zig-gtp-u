// GTP-U Path Management with RTT Monitoring
// 3GPP TS 29.281 Section 4.4

const std = @import("std");
const message = @import("message.zig");

pub const PathState = enum {
    unknown,
    active,
    suspect,
    failed,
};

pub const PathStats = struct {
    echo_requests_sent: u64 = 0,
    echo_responses_received: u64 = 0,
    rtt_samples: u32 = 0,
    min_rtt_us: u64 = std.math.maxInt(u64),
    max_rtt_us: u64 = 0,
    avg_rtt_us: u64 = 0,
    last_rtt_us: u64 = 0,

    pub fn updateRtt(self: *PathStats, rtt_us: u64) void {
        self.rtt_samples += 1;
        self.last_rtt_us = rtt_us;

        if (rtt_us < self.min_rtt_us) {
            self.min_rtt_us = rtt_us;
        }
        if (rtt_us > self.max_rtt_us) {
            self.max_rtt_us = rtt_us;
        }

        // Update running average
        const old_avg = self.avg_rtt_us;
        const n = self.rtt_samples;
        self.avg_rtt_us = (old_avg * (n - 1) + rtt_us) / n;
    }

    pub fn packetLossRate(self: PathStats) f64 {
        if (self.echo_requests_sent == 0) return 0.0;
        const lost = self.echo_requests_sent - self.echo_responses_received;
        return @as(f64, @floatFromInt(lost)) / @as(f64, @floatFromInt(self.echo_requests_sent));
    }
};

pub const PathConfig = struct {
    echo_interval_ms: u64 = 60000,      // Echo request interval (1 minute)
    echo_timeout_ms: u64 = 5000,        // Echo response timeout (5 seconds)
    max_echo_failures: u32 = 3,         // Max consecutive failures before marking path as failed
    suspect_threshold_ms: u64 = 10000,  // RTT threshold for suspect state (10ms)
};

pub const Path = struct {
    peer_address: std.net.Address,
    state: PathState,
    stats: PathStats,
    config: PathConfig,

    last_echo_time: i128 = 0,
    last_response_time: i128 = 0,
    consecutive_failures: u32 = 0,
    current_sequence: u16 = 0,
    pending_echo: ?PendingEcho = null,

    mutex: std.Thread.Mutex = .{},

    pub const PendingEcho = struct {
        sequence: u16,
        sent_time: i128,
    };

    pub fn init(peer_address: std.net.Address, config: PathConfig) Path {
        return .{
            .peer_address = peer_address,
            .state = .unknown,
            .stats = .{},
            .config = config,
        };
    }

    pub fn needsEcho(self: *Path, current_time: i128) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Don't send if we have a pending echo
        if (self.pending_echo != null) {
            return false;
        }

        const elapsed_ms = @as(u64, @intCast(current_time - self.last_echo_time)) / std.time.ns_per_ms;
        return elapsed_ms >= self.config.echo_interval_ms;
    }

    pub fn sendEcho(self: *Path, current_time: i128) u16 {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.current_sequence +%= 1;
        self.pending_echo = .{
            .sequence = self.current_sequence,
            .sent_time = current_time,
        };
        self.last_echo_time = current_time;
        self.stats.echo_requests_sent += 1;

        return self.current_sequence;
    }

    pub fn receiveEchoResponse(self: *Path, sequence: u16, current_time: i128) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pending_echo) |pending| {
            if (pending.sequence != sequence) {
                return error.SequenceMismatch;
            }

            // Calculate RTT
            const rtt_ns = current_time - pending.sent_time;
            const rtt_us: u64 = @intCast(@divTrunc(rtt_ns, std.time.ns_per_us));

            self.stats.updateRtt(rtt_us);
            self.stats.echo_responses_received += 1;
            self.last_response_time = current_time;
            self.consecutive_failures = 0;
            self.pending_echo = null;

            // Update path state based on RTT
            if (rtt_us > self.config.suspect_threshold_ms * 1000) {
                self.state = .suspect;
            } else {
                self.state = .active;
            }
        }
    }

    pub fn checkTimeout(self: *Path, current_time: i128) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pending_echo) |pending| {
            const elapsed_ms: u64 = @intCast(@divTrunc(current_time - pending.sent_time, std.time.ns_per_ms));

            if (elapsed_ms > self.config.echo_timeout_ms) {
                // Echo timeout
                self.consecutive_failures += 1;
                self.pending_echo = null;

                if (self.consecutive_failures >= self.config.max_echo_failures) {
                    self.state = .failed;
                } else {
                    self.state = .suspect;
                }
            }
        }
    }

    pub fn isHealthy(self: *Path) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state == .active;
    }

    pub fn getStats(self: *Path) PathStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }
};

pub const PathManager = struct {
    paths: std.AutoHashMap(u64, Path),
    allocator: std.mem.Allocator,
    config: PathConfig,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, config: PathConfig) PathManager {
        return .{
            .paths = std.AutoHashMap(u64, Path).init(allocator),
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *PathManager) void {
        self.paths.deinit();
    }

    fn addressHash(address: std.net.Address) u64 {
        var hasher = std.hash.Wyhash.init(0);

        switch (address.any.family) {
            std.posix.AF.INET => {
                hasher.update(std.mem.asBytes(&address.in.sa.addr));
                hasher.update(std.mem.asBytes(&address.in.sa.port));
            },
            std.posix.AF.INET6 => {
                hasher.update(&address.in6.sa.addr);
                hasher.update(std.mem.asBytes(&address.in6.sa.port));
            },
            else => {},
        }

        return hasher.final();
    }

    pub fn getOrCreatePath(self: *PathManager, peer_address: std.net.Address) !*Path {
        self.mutex.lock();
        defer self.mutex.unlock();

        const hash = addressHash(peer_address);
        const entry = try self.paths.getOrPut(hash);

        if (!entry.found_existing) {
            entry.value_ptr.* = Path.init(peer_address, self.config);
        }

        return entry.value_ptr;
    }

    pub fn getPath(self: *PathManager, peer_address: std.net.Address) ?*Path {
        self.mutex.lock();
        defer self.mutex.unlock();

        const hash = addressHash(peer_address);
        return self.paths.getPtr(hash);
    }

    pub fn removePath(self: *PathManager, peer_address: std.net.Address) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const hash = addressHash(peer_address);
        _ = self.paths.remove(hash);
    }

    pub fn processEchos(self: *PathManager, current_time: i128, send_callback: *const fn (std.net.Address, u16) void) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.paths.valueIterator();
        while (it.next()) |path| {
            // Check for timeouts
            path.checkTimeout(current_time);

            // Send echo if needed
            if (path.needsEcho(current_time)) {
                const sequence = path.sendEcho(current_time);
                send_callback(path.peer_address, sequence);
            }
        }
    }

    pub fn getHealthyPaths(self: *PathManager, allocator: std.mem.Allocator) ![]std.net.Address {
        self.mutex.lock();
        defer self.mutex.unlock();

        var healthy = std.ArrayList(std.net.Address).init(allocator);
        errdefer healthy.deinit();

        var it = self.paths.valueIterator();
        while (it.next()) |path| {
            if (path.isHealthy()) {
                try healthy.append(path.peer_address);
            }
        }

        return healthy.toOwnedSlice();
    }
};

test "Path RTT statistics" {
    var path = Path.init(try std.net.Address.parseIp("192.168.1.1", 2152), .{});

    // Simulate RTT measurements
    path.stats.updateRtt(1000); // 1ms
    path.stats.updateRtt(1500); // 1.5ms
    path.stats.updateRtt(2000); // 2ms

    try std.testing.expectEqual(@as(u32, 3), path.stats.rtt_samples);
    try std.testing.expectEqual(@as(u64, 1000), path.stats.min_rtt_us);
    try std.testing.expectEqual(@as(u64, 2000), path.stats.max_rtt_us);
    try std.testing.expectEqual(@as(u64, 1500), path.stats.avg_rtt_us);
}

test "PathManager path lifecycle" {
    const allocator = std.testing.allocator;

    var manager = PathManager.init(allocator, .{});
    defer manager.deinit();

    const addr1 = try std.net.Address.parseIp("192.168.1.1", 2152);
    const addr2 = try std.net.Address.parseIp("192.168.1.2", 2152);

    // Create paths
    _ = try manager.getOrCreatePath(addr1);
    _ = try manager.getOrCreatePath(addr2);

    // Verify paths exist
    try std.testing.expect(manager.getPath(addr1) != null);
    try std.testing.expect(manager.getPath(addr2) != null);

    // Remove path
    manager.removePath(addr1);
    try std.testing.expect(manager.getPath(addr1) == null);
    try std.testing.expect(manager.getPath(addr2) != null);
}
