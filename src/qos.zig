// QoS Flow Support for 5G
// 3GPP TS 23.501 - 5G QoS

const std = @import("std");

// 5G QoS Identifier (5QI) values as per 3GPP TS 23.501 Table 5.7.4-1
pub const QosCharacteristics = enum(u8) {
    // GBR Resource Types
    conversational_voice = 1,              // Voice
    conversational_video = 2,              // Live streaming
    real_time_gaming = 3,                  // Real-time gaming
    non_conversational_video = 4,          // Buffered streaming
    ims_signaling = 5,                     // IMS signaling
    video_buffered_streaming = 6,          // Video (buffered)
    voice_premium = 7,                     // Premium voice
    video_interactive_gaming = 8,          // Interactive gaming
    video_non_conversational = 9,          // Non-conversational video (buffered)

    // Non-GBR Resource Types
    default_bearer = 10,                    // Default bearer (reused value)
    ims_video = 65,                        // IMS video
    tcp_based = 66,                        // TCP-based (web, email, etc.)
    live_video_streaming = 67,             // Live video streaming
    premium_messaging = 69,                // Premium messaging
    mission_critical_push_to_talk = 70,   // MCPTT
    mission_critical_video = 71,           // Mission critical video
    mission_critical_data = 72,            // Mission critical data
    v2x_messages = 73,                     // V2X messages
    low_latency_embb = 74,                 // Low latency eMBB
    ultra_low_latency = 75,                // Ultra-low latency eMBB
    electricity_distribution = 76,         // Electricity distribution

    _,

    pub fn isGbr(self: QosCharacteristics) bool {
        return @intFromEnum(self) <= 9 and @intFromEnum(self) >= 1;
    }

    pub fn isDelayReliant(self: QosCharacteristics) bool {
        return switch (self) {
            .conversational_voice,
            .conversational_video,
            .real_time_gaming,
            .ims_signaling,
            .mission_critical_push_to_talk,
            .mission_critical_video,
            .v2x_messages,
            .ultra_low_latency => true,
            else => false,
        };
    }
};

// Allocation and Retention Priority
pub const AllocationRetentionPriority = struct {
    priority_level: u4,          // 1 (highest) to 15 (lowest)
    preemption_capability: bool, // Can preempt other bearers
    preemption_vulnerability: bool, // Can be preempted

    pub fn init(priority: u4) AllocationRetentionPriority {
        return .{
            .priority_level = priority,
            .preemption_capability = false,
            .preemption_vulnerability = true,
        };
    }
};

// QoS Flow Identifier (QFI)
pub const QFI = u6; // 0-63, where 0 is reserved

// QoS Flow parameters
pub const QosFlowParams = struct {
    qfi: QFI,
    fiveqi: QosCharacteristics,
    arp: AllocationRetentionPriority,

    // GBR parameters (if applicable)
    gfbr_uplink: ?u64 = null,      // Guaranteed Flow Bit Rate - Uplink (bps)
    gfbr_downlink: ?u64 = null,    // Guaranteed Flow Bit Rate - Downlink (bps)
    mfbr_uplink: ?u64 = null,      // Maximum Flow Bit Rate - Uplink (bps)
    mfbr_downlink: ?u64 = null,    // Maximum Flow Bit Rate - Downlink (bps)

    // Additional parameters
    packet_delay_budget: u16 = 100,    // Milliseconds
    packet_error_rate: u8 = 3,         // 10^-x
    averaging_window: u16 = 2000,      // Milliseconds

    pub fn isGbr(self: QosFlowParams) bool {
        return self.fiveqi.isGbr();
    }

    pub fn validate(self: QosFlowParams) !void {
        if (self.qfi > 63) {
            return error.InvalidQfi;
        }

        if (self.isGbr()) {
            if (self.gfbr_uplink == null or self.gfbr_downlink == null) {
                return error.MissingGbrParameters;
            }
        }

        if (self.arp.priority_level > 15 or self.arp.priority_level < 1) {
            return error.InvalidArpPriority;
        }
    }
};

// QoS Flow statistics
pub const QosFlowStats = struct {
    packets_transmitted: u64 = 0,
    packets_received: u64 = 0,
    bytes_transmitted: u64 = 0,
    bytes_received: u64 = 0,
    packets_dropped: u64 = 0,
    packets_delayed: u64 = 0,

    // Timing statistics
    min_delay_us: u64 = std.math.maxInt(u64),
    max_delay_us: u64 = 0,
    avg_delay_us: u64 = 0,
    delay_samples: u64 = 0,

    mutex: std.Thread.Mutex = .{},

    pub fn recordPacket(self: *QosFlowStats, bytes: usize, delay_us: u64, is_tx: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (is_tx) {
            self.packets_transmitted += 1;
            self.bytes_transmitted += bytes;
        } else {
            self.packets_received += 1;
            self.bytes_received += bytes;
        }

        // Update delay statistics
        self.delay_samples += 1;
        if (delay_us < self.min_delay_us) {
            self.min_delay_us = delay_us;
        }
        if (delay_us > self.max_delay_us) {
            self.max_delay_us = delay_us;
        }

        const old_avg = self.avg_delay_us;
        const n = self.delay_samples;
        self.avg_delay_us = (old_avg * (n - 1) + delay_us) / n;
    }

    pub fn recordDrop(self: *QosFlowStats) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.packets_dropped += 1;
    }

    pub fn packetLossRate(self: *QosFlowStats) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const total = self.packets_transmitted + self.packets_dropped;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.packets_dropped)) / @as(f64, @floatFromInt(total));
    }

    pub fn throughputBps(self: *QosFlowStats, elapsed_seconds: f64) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (elapsed_seconds <= 0.0) return 0.0;
        const total_bytes = self.bytes_transmitted + self.bytes_received;
        return @as(f64, @floatFromInt(total_bytes)) * 8.0 / elapsed_seconds;
    }
};

// QoS Flow
pub const QosFlow = struct {
    params: QosFlowParams,
    stats: QosFlowStats,
    active: bool = true,

    pub fn init(params: QosFlowParams) !QosFlow {
        try params.validate();

        return .{
            .params = params,
            .stats = .{},
        };
    }

    pub fn canAcceptPacket(self: *QosFlow, packet_size: usize) bool {
        _ = packet_size;
        return self.active;
    }

    pub fn shouldDrop(self: *QosFlow) bool {
        // Simple rate limiting check
        if (!self.active) return true;

        // Check if we're exceeding packet error rate
        const plr = self.stats.packetLossRate();
        const threshold = std.math.pow(f64, 10.0, -@as(f64, @floatFromInt(self.params.packet_error_rate)));

        return plr > threshold * 1.5; // Allow 50% margin
    }

    pub fn exceedsDelayBudget(self: *QosFlow) bool {
        self.stats.mutex.lock();
        defer self.stats.mutex.unlock();

        const avg_delay_ms = self.stats.avg_delay_us / 1000;
        return avg_delay_ms > self.params.packet_delay_budget;
    }
};

// QoS Flow Manager
pub const QosFlowManager = struct {
    flows: std.AutoHashMap(QFI, QosFlow),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) QosFlowManager {
        return .{
            .flows = std.AutoHashMap(QFI, QosFlow).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *QosFlowManager) void {
        self.flows.deinit();
    }

    pub fn createFlow(self: *QosFlowManager, params: QosFlowParams) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const flow = try QosFlow.init(params);
        try self.flows.put(params.qfi, flow);
    }

    pub fn removeFlow(self: *QosFlowManager, qfi: QFI) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        _ = self.flows.remove(qfi);
    }

    pub fn getFlow(self: *QosFlowManager, qfi: QFI) ?*QosFlow {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.flows.getPtr(qfi);
    }

    pub fn classifyPacket(self: *QosFlowManager, packet_data: []const u8) QFI {
        _ = packet_data;
        _ = self;

        // Default QFI for unclassified traffic
        // In a real implementation, this would perform DPI or use flow rules
        return 9; // Default bearer
    }

    pub fn getActiveFlows(self: *QosFlowManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var it = self.flows.valueIterator();
        while (it.next()) |flow| {
            if (flow.active) count += 1;
        }
        return count;
    }
};

test "QoS characteristics" {
    try std.testing.expect(QosCharacteristics.conversational_voice.isGbr());
    try std.testing.expect(!QosCharacteristics.tcp_based.isGbr());
    try std.testing.expect(QosCharacteristics.conversational_voice.isDelayReliant());
}

test "QoS flow validation" {
    // Valid non-GBR flow
    const flow1 = QosFlowParams{
        .qfi = 9,
        .fiveqi = .default_bearer,
        .arp = AllocationRetentionPriority.init(5),
    };
    try flow1.validate();

    // Invalid QFI
    const flow2 = QosFlowParams{
        .qfi = 100,
        .fiveqi = .default_bearer,
        .arp = AllocationRetentionPriority.init(5),
    };
    try std.testing.expectError(error.InvalidQfi, flow2.validate());
}

test "QoS flow manager" {
    const allocator = std.testing.allocator;

    var manager = QosFlowManager.init(allocator);
    defer manager.deinit();

    const params = QosFlowParams{
        .qfi = 9,
        .fiveqi = .default_bearer,
        .arp = AllocationRetentionPriority.init(5),
    };

    try manager.createFlow(params);
    try std.testing.expect(manager.getFlow(9) != null);
    try std.testing.expectEqual(@as(usize, 1), manager.getActiveFlows());

    manager.removeFlow(9);
    try std.testing.expect(manager.getFlow(9) == null);
}
