// GTP-U Tunnel Management with State Machine
// 3GPP TS 29.281

const std = @import("std");
const qos = @import("qos.zig");

// Tunnel state as per 3GPP lifecycle
pub const TunnelState = enum {
    inactive,      // Not yet established
    establishing,  // Being established
    active,        // Fully operational
    modifying,     // Being modified
    releasing,     // Being released
    released,      // Released/deleted

    pub fn canTransitionTo(self: TunnelState, target: TunnelState) bool {
        return switch (self) {
            .inactive => target == .establishing,
            .establishing => target == .active or target == .releasing,
            .active => target == .modifying or target == .releasing,
            .modifying => target == .active or target == .releasing,
            .releasing => target == .released,
            .released => false,
        };
    }
};

// Tunnel statistics
pub const TunnelStats = struct {
    packets_tx: u64 = 0,
    packets_rx: u64 = 0,
    bytes_tx: u64 = 0,
    bytes_rx: u64 = 0,
    errors: u64 = 0,
    created_at: i128 = 0,
    last_activity: i128 = 0,

    mutex: std.Thread.Mutex = .{},

    pub fn recordTx(self: *TunnelStats, bytes: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.packets_tx += 1;
        self.bytes_tx += bytes;
        self.last_activity = std.time.nanoTimestamp();
    }

    pub fn recordRx(self: *TunnelStats, bytes: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.packets_rx += 1;
        self.bytes_rx += bytes;
        self.last_activity = std.time.nanoTimestamp();
    }

    pub fn recordError(self: *TunnelStats) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.errors += 1;
    }

    pub fn getLifetime(self: *TunnelStats) i128 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return std.time.nanoTimestamp() - self.created_at;
    }

    pub fn getIdleTime(self: *TunnelStats) i128 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return std.time.nanoTimestamp() - self.last_activity;
    }
};

// Tunnel Endpoint Identifier (TEID)
pub const TEID = u32;

// Tunnel configuration
pub const TunnelConfig = struct {
    local_teid: TEID,
    remote_teid: TEID,
    local_address: std.net.Address,
    remote_address: std.net.Address,
    idle_timeout_ns: i128 = 300 * std.time.ns_per_s, // 5 minutes

    pub fn validate(self: TunnelConfig) !void {
        if (self.local_teid == 0) {
            return error.InvalidLocalTeid;
        }
        // Note: remote_teid can be 0 for certain signaling messages
    }
};

// GTP-U Tunnel
pub const Tunnel = struct {
    config: TunnelConfig,
    state: TunnelState,
    stats: TunnelStats,
    qos_flows: std.ArrayList(qos.QFI),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    // Anti-replay protection (optional)
    last_sequence: ?u16 = null,
    replay_window: u64 = 0, // Bitmap for out-of-order detection

    pub fn init(allocator: std.mem.Allocator, config: TunnelConfig) !Tunnel {
        try config.validate();

        return .{
            .config = config,
            .state = .inactive,
            .stats = .{
                .created_at = std.time.nanoTimestamp(),
                .last_activity = std.time.nanoTimestamp(),
            },
            .qos_flows = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Tunnel) void {
        self.qos_flows.deinit(self.allocator);
    }

    pub fn transitionTo(self: *Tunnel, new_state: TunnelState) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (!self.state.canTransitionTo(new_state)) {
            return error.InvalidStateTransition;
        }

        self.state = new_state;
    }

    pub fn activate(self: *Tunnel) !void {
        try self.transitionTo(.establishing);
        try self.transitionTo(.active);
    }

    pub fn release(self: *Tunnel) !void {
        try self.transitionTo(.releasing);
        try self.transitionTo(.released);
    }

    pub fn addQosFlow(self: *Tunnel, qfi: qos.QFI) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already exists
        for (self.qos_flows.items) |existing_qfi| {
            if (existing_qfi == qfi) return;
        }

        try self.qos_flows.append(self.allocator, qfi);
    }

    pub fn removeQosFlow(self: *Tunnel, qfi: qos.QFI) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.qos_flows.items, 0..) |existing_qfi, i| {
            if (existing_qfi == qfi) {
                _ = self.qos_flows.orderedRemove(i);
                return;
            }
        }
    }

    pub fn isIdle(self: *Tunnel) bool {
        return self.stats.getIdleTime() > self.config.idle_timeout_ns;
    }

    pub fn isActive(self: *Tunnel) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state == .active;
    }

    pub fn checkSequence(self: *Tunnel, sequence: u16) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.last_sequence) |last| {
            // Simple anti-replay check
            const diff = sequence -% last;
            if (diff == 0 or diff > 32768) {
                // Duplicate or very old packet
                return false;
            }
        }

        self.last_sequence = sequence;
        return true;
    }
};

// Tunnel Manager
pub const TunnelManager = struct {
    tunnels: std.AutoHashMap(TEID, Tunnel),
    allocator: std.mem.Allocator,
    teid_counter: std.atomic.Value(u32) = std.atomic.Value(u32).init(0x1000),
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) TunnelManager {
        return .{
            .tunnels = std.AutoHashMap(TEID, Tunnel).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TunnelManager) void {
        var it = self.tunnels.valueIterator();
        while (it.next()) |tunnel| {
            tunnel.deinit();
        }
        self.tunnels.deinit();
    }

    pub fn allocateTeid(self: *TunnelManager) TEID {
        // Thread-safe TEID allocation
        return self.teid_counter.fetchAdd(1, .monotonic);
    }

    pub fn createTunnel(self: *TunnelManager, config: TunnelConfig) !TEID {
        self.mutex.lock();
        defer self.mutex.unlock();

        var tunnel = try Tunnel.init(self.allocator, config);
        errdefer tunnel.deinit();

        try tunnel.activate();
        try self.tunnels.put(config.local_teid, tunnel);

        return config.local_teid;
    }

    pub fn getTunnel(self: *TunnelManager, teid: TEID) ?*Tunnel {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.tunnels.getPtr(teid);
    }

    pub fn removeTunnel(self: *TunnelManager, teid: TEID) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tunnels.getPtr(teid)) |tunnel| {
            try tunnel.release();
            tunnel.deinit();
            _ = self.tunnels.remove(teid);
        }
    }

    pub fn getTunnelCount(self: *TunnelManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.tunnels.count();
    }

    pub fn getActiveTunnels(self: *TunnelManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var it = self.tunnels.valueIterator();
        while (it.next()) |tunnel| {
            if (tunnel.isActive()) count += 1;
        }
        return count;
    }

    pub fn cleanupIdleTunnels(self: *TunnelManager) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var to_remove: std.ArrayList(TEID) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.tunnels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isIdle()) {
                try to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (to_remove.items) |teid| {
            if (self.tunnels.getPtr(teid)) |tunnel| {
                tunnel.deinit();
                _ = self.tunnels.remove(teid);
            }
        }

        return to_remove.items.len;
    }

    pub fn updateStats(self: *TunnelManager, teid: TEID, bytes: usize, is_tx: bool) void {
        if (self.getTunnel(teid)) |tunnel| {
            if (is_tx) {
                tunnel.stats.recordTx(bytes);
            } else {
                tunnel.stats.recordRx(bytes);
            }
        }
    }
};

test "Tunnel state machine" {
    const allocator = std.testing.allocator;

    const config = TunnelConfig{
        .local_teid = 0x1234,
        .remote_teid = 0x5678,
        .local_address = try std.net.Address.parseIp("192.168.1.1", 2152),
        .remote_address = try std.net.Address.parseIp("192.168.1.2", 2152),
    };

    var tunnel = try Tunnel.init(allocator, config);
    defer tunnel.deinit();

    try std.testing.expectEqual(TunnelState.inactive, tunnel.state);

    try tunnel.activate();
    try std.testing.expectEqual(TunnelState.active, tunnel.state);

    try tunnel.release();
    try std.testing.expectEqual(TunnelState.released, tunnel.state);
}

test "Tunnel manager lifecycle" {
    const allocator = std.testing.allocator;

    var manager = TunnelManager.init(allocator);
    defer manager.deinit();

    const config = TunnelConfig{
        .local_teid = manager.allocateTeid(),
        .remote_teid = 0x5678,
        .local_address = try std.net.Address.parseIp("192.168.1.1", 2152),
        .remote_address = try std.net.Address.parseIp("192.168.1.2", 2152),
    };

    const teid = try manager.createTunnel(config);
    try std.testing.expectEqual(@as(usize, 1), manager.getTunnelCount());
    try std.testing.expectEqual(@as(usize, 1), manager.getActiveTunnels());

    const tunnel = manager.getTunnel(teid);
    try std.testing.expect(tunnel != null);
    try std.testing.expect(tunnel.?.isActive());

    try manager.removeTunnel(teid);
    try std.testing.expectEqual(@as(usize, 0), manager.getTunnelCount());
}

test "Tunnel QoS flow management" {
    const allocator = std.testing.allocator;

    const config = TunnelConfig{
        .local_teid = 0x1234,
        .remote_teid = 0x5678,
        .local_address = try std.net.Address.parseIp("192.168.1.1", 2152),
        .remote_address = try std.net.Address.parseIp("192.168.1.2", 2152),
    };

    var tunnel = try Tunnel.init(allocator, config);
    defer tunnel.deinit();

    try tunnel.addQosFlow(9);
    try tunnel.addQosFlow(5);

    try std.testing.expectEqual(@as(usize, 2), tunnel.qos_flows.items.len);

    tunnel.removeQosFlow(9);
    try std.testing.expectEqual(@as(usize, 1), tunnel.qos_flows.items.len);
}
