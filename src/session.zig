// GTP-U Session Management
// Manages PDU sessions and their associated tunnels

const std = @import("std");
const tunnel = @import("tunnel.zig");
const qos = @import("qos.zig");

// PDU Session ID
pub const PduSessionId = u8; // 0-255

// PDU Session Type
pub const PduSessionType = enum {
    ipv4,
    ipv6,
    ipv4v6,
    ethernet,
    unstructured,
};

// PDU Session state
pub const SessionState = enum {
    inactive,
    establishing,
    active,
    modifying,
    releasing,
    released,
};

// PDU Session
pub const PduSession = struct {
    id: PduSessionId,
    session_type: PduSessionType,
    state: SessionState,

    // Associated tunnels (N3 uplink/downlink)
    uplink_tunnel: ?tunnel.TEID = null,
    downlink_tunnel: ?tunnel.TEID = null,

    // QoS flows
    qos_manager: qos.QosFlowManager,

    // UE information
    ue_ip: ?std.net.Address = null,
    dnn: []const u8, // Data Network Name (APN in 4G)

    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    created_at: i128,
    modified_at: i128,

    pub fn init(
        allocator: std.mem.Allocator,
        id: PduSessionId,
        session_type: PduSessionType,
        dnn: []const u8,
    ) !PduSession {
        const now = std.time.nanoTimestamp();

        return .{
            .id = id,
            .session_type = session_type,
            .state = .inactive,
            .qos_manager = qos.QosFlowManager.init(allocator),
            .dnn = try allocator.dupe(u8, dnn),
            .allocator = allocator,
            .created_at = now,
            .modified_at = now,
        };
    }

    pub fn deinit(self: *PduSession) void {
        self.qos_manager.deinit();
        self.allocator.free(self.dnn);
    }

    pub fn setUplinkTunnel(self: *PduSession, teid: tunnel.TEID) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.uplink_tunnel = teid;
        self.modified_at = std.time.nanoTimestamp();
    }

    pub fn setDownlinkTunnel(self: *PduSession, teid: tunnel.TEID) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.downlink_tunnel = teid;
        self.modified_at = std.time.nanoTimestamp();
    }

    pub fn addQosFlow(self: *PduSession, params: qos.QosFlowParams) !void {
        try self.qos_manager.createFlow(params);
        self.modified_at = std.time.nanoTimestamp();
    }

    pub fn removeQosFlow(self: *PduSession, qfi: qos.QFI) void {
        self.qos_manager.removeFlow(qfi);
        self.modified_at = std.time.nanoTimestamp();
    }

    pub fn activate(self: *PduSession) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .inactive and self.state != .establishing) {
            return error.InvalidStateTransition;
        }

        if (self.uplink_tunnel == null or self.downlink_tunnel == null) {
            return error.TunnelsNotConfigured;
        }

        self.state = .active;
        self.modified_at = std.time.nanoTimestamp();
    }

    pub fn release(self: *PduSession) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.state = .releasing;
        self.modified_at = std.time.nanoTimestamp();
    }

    pub fn isActive(self: *PduSession) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state == .active;
    }
};

// Session Manager
pub const SessionManager = struct {
    sessions: std.AutoHashMap(PduSessionId, PduSession),
    tunnel_manager: *tunnel.TunnelManager,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, tunnel_mgr: *tunnel.TunnelManager) SessionManager {
        return .{
            .sessions = std.AutoHashMap(PduSessionId, PduSession).init(allocator),
            .tunnel_manager = tunnel_mgr,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionManager) void {
        var it = self.sessions.valueIterator();
        while (it.next()) |session| {
            session.deinit();
        }
        self.sessions.deinit();
    }

    pub fn createSession(
        self: *SessionManager,
        id: PduSessionId,
        session_type: PduSessionType,
        dnn: []const u8,
        local_addr: std.net.Address,
        remote_addr: std.net.Address,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if session already exists
        if (self.sessions.contains(id)) {
            return error.SessionAlreadyExists;
        }

        // Create session
        var session = try PduSession.init(self.allocator, id, session_type, dnn);
        errdefer session.deinit();

        // Create uplink tunnel (gNB -> UPF)
        const ul_config = tunnel.TunnelConfig{
            .local_teid = self.tunnel_manager.allocateTeid(),
            .remote_teid = 0, // Will be set later
            .local_address = local_addr,
            .remote_address = remote_addr,
        };
        const ul_teid = try self.tunnel_manager.createTunnel(ul_config);

        // Create downlink tunnel (UPF -> gNB)
        const dl_config = tunnel.TunnelConfig{
            .local_teid = self.tunnel_manager.allocateTeid(),
            .remote_teid = 0, // Will be set later
            .local_address = local_addr,
            .remote_address = remote_addr,
        };
        const dl_teid = try self.tunnel_manager.createTunnel(dl_config);

        session.setUplinkTunnel(ul_teid);
        session.setDownlinkTunnel(dl_teid);

        try self.sessions.put(id, session);
    }

    pub fn getSession(self: *SessionManager, id: PduSessionId) ?*PduSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.sessions.getPtr(id);
    }

    pub fn removeSession(self: *SessionManager, id: PduSessionId) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.getPtr(id)) |session| {
            // Release tunnels
            if (session.uplink_tunnel) |ul_teid| {
                try self.tunnel_manager.removeTunnel(ul_teid);
            }
            if (session.downlink_tunnel) |dl_teid| {
                try self.tunnel_manager.removeTunnel(dl_teid);
            }

            session.deinit();
            _ = self.sessions.remove(id);
        }
    }

    pub fn getSessionCount(self: *SessionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.count();
    }

    pub fn getActiveSessions(self: *SessionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var it = self.sessions.valueIterator();
        while (it.next()) |session| {
            if (session.isActive()) count += 1;
        }
        return count;
    }

    pub fn findSessionByTeid(self: *SessionManager, teid: tunnel.TEID) ?*PduSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.sessions.valueIterator();
        while (it.next()) |session| {
            if (session.uplink_tunnel == teid or session.downlink_tunnel == teid) {
                return session;
            }
        }
        return null;
    }
};

test "PDU Session lifecycle" {
    const allocator = std.testing.allocator;

    var session = try PduSession.init(allocator, 1, .ipv4, "internet");
    defer session.deinit();

    try std.testing.expectEqual(@as(u8, 1), session.id);
    try std.testing.expectEqual(PduSessionType.ipv4, session.session_type);
    try std.testing.expectEqual(SessionState.inactive, session.state);
    try std.testing.expectEqualStrings("internet", session.dnn);
}

test "Session Manager lifecycle" {
    const allocator = std.testing.allocator;

    var tunnel_mgr = tunnel.TunnelManager.init(allocator);
    defer tunnel_mgr.deinit();

    var session_mgr = SessionManager.init(allocator, &tunnel_mgr);
    defer session_mgr.deinit();

    const local_addr = try std.net.Address.parseIp("192.168.1.1", 2152);
    const remote_addr = try std.net.Address.parseIp("192.168.1.2", 2152);

    try session_mgr.createSession(1, .ipv4, "internet", local_addr, remote_addr);

    try std.testing.expectEqual(@as(usize, 1), session_mgr.getSessionCount());

    const session = session_mgr.getSession(1);
    try std.testing.expect(session != null);
    try std.testing.expect(session.?.uplink_tunnel != null);
    try std.testing.expect(session.?.downlink_tunnel != null);

    try session_mgr.removeSession(1);
    try std.testing.expectEqual(@as(usize, 0), session_mgr.getSessionCount());
}

test "Session with QoS flows" {
    const allocator = std.testing.allocator;

    var session = try PduSession.init(allocator, 1, .ipv4, "internet");
    defer session.deinit();

    const qos_params = qos.QosFlowParams{
        .qfi = 9,
        .fiveqi = .default_bearer,
        .arp = qos.AllocationRetentionPriority.init(5),
    };

    try session.addQosFlow(qos_params);
    try std.testing.expectEqual(@as(usize, 1), session.qos_manager.getActiveFlows());

    session.removeQosFlow(9);
    try std.testing.expectEqual(@as(usize, 0), session.qos_manager.getActiveFlows());
}

test "IPv6 PDU Session" {
    const allocator = std.testing.allocator;

    var session = try PduSession.init(allocator, 2, .ipv6, "internet");
    defer session.deinit();

    try std.testing.expectEqual(@as(u8, 2), session.id);
    try std.testing.expectEqual(PduSessionType.ipv6, session.session_type);
    try std.testing.expectEqual(SessionState.inactive, session.state);
    try std.testing.expectEqualStrings("internet", session.dnn);
}

test "Dual-stack IPv4v6 PDU Session" {
    const allocator = std.testing.allocator;

    var session = try PduSession.init(allocator, 3, .ipv4v6, "internet");
    defer session.deinit();

    try std.testing.expectEqual(@as(u8, 3), session.id);
    try std.testing.expectEqual(PduSessionType.ipv4v6, session.session_type);
    try std.testing.expectEqual(SessionState.inactive, session.state);
}

test "Session Manager with IPv6" {
    const allocator = std.testing.allocator;

    var tunnel_mgr = tunnel.TunnelManager.init(allocator);
    defer tunnel_mgr.deinit();

    var session_mgr = SessionManager.init(allocator, &tunnel_mgr);
    defer session_mgr.deinit();

    const local_addr = try std.net.Address.parseIp6("2001:db8::1", 2152);
    const remote_addr = try std.net.Address.parseIp6("2001:db8::2", 2152);

    try session_mgr.createSession(1, .ipv6, "internet", local_addr, remote_addr);

    try std.testing.expectEqual(@as(usize, 1), session_mgr.getSessionCount());

    const session = session_mgr.getSession(1);
    try std.testing.expect(session != null);
    try std.testing.expectEqual(PduSessionType.ipv6, session.?.session_type);
    try std.testing.expect(session.?.uplink_tunnel != null);
    try std.testing.expect(session.?.downlink_tunnel != null);

    try session_mgr.removeSession(1);
    try std.testing.expectEqual(@as(usize, 0), session_mgr.getSessionCount());
}
