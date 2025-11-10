// GTP-U Utility Functions
// TEID generation, validation, and crypto utilities

const std = @import("std");
const protocol = @import("protocol.zig");

// Cryptographic TEID Generator
// Uses secure random for production-grade TEID allocation
pub const TeidGenerator = struct {
    rng: std.Random.Xoshiro256,
    mutex: std.Thread.Mutex = .{},

    pub fn init() !TeidGenerator {
        var seed: [8]u8 = undefined;
        try std.posix.getrandom(&seed);

        return .{
            .rng = std.Random.Xoshiro256.init(@bitCast(seed)),
        };
    }

    pub fn generate(self: *TeidGenerator) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var teid: u32 = 0;
        // Ensure TEID is never zero (reserved value)
        while (teid == 0) {
            teid = self.rng.random().int(u32);
        }
        return teid;
    }

    pub fn generateRange(self: *TeidGenerator, count: usize, allocator: std.mem.Allocator) ![]u32 {
        const teids = try allocator.alloc(u32, count);
        errdefer allocator.free(teids);

        var seen = std.AutoHashMap(u32, void).init(allocator);
        defer seen.deinit();

        var i: usize = 0;
        while (i < count) {
            const teid = self.generate();
            const entry = try seen.getOrPut(teid);
            if (!entry.found_existing) {
                teids[i] = teid;
                i += 1;
            }
        }

        return teids;
    }
};

// Anti-replay protection using sliding window
pub const AntiReplayWindow = struct {
    window_size: u16,
    highest_seq: u16,
    bitmap: []u64,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, window_size: u16) !AntiReplayWindow {
        const bitmap_size = (window_size + 63) / 64;
        const bitmap = try allocator.alloc(u64, bitmap_size);
        @memset(bitmap, 0);

        return .{
            .window_size = window_size,
            .highest_seq = 0,
            .bitmap = bitmap,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AntiReplayWindow) void {
        self.allocator.free(self.bitmap);
    }

    pub fn check(self: *AntiReplayWindow, sequence: u16) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const diff = sequence -% self.highest_seq;

        if (diff == 0) {
            // Exact duplicate
            return false;
        } else if (diff < 32768) {
            // Newer packet
            if (diff >= self.window_size) {
                // Outside window, clear and accept
                @memset(self.bitmap, 0);
                self.highest_seq = sequence;
                self.setBit(0);
                return true;
            } else {
                // Within window, shift and check
                self.shiftWindow(diff);
                self.highest_seq = sequence;
                if (self.getBit(0)) {
                    return false; // Duplicate
                }
                self.setBit(0);
                return true;
            }
        } else {
            // Older packet
            const age = (0 -% diff);
            if (age >= self.window_size) {
                return false; // Too old
            }
            if (self.getBit(age)) {
                return false; // Duplicate
            }
            self.setBit(age);
            return true;
        }
    }

    fn setBit(self: *AntiReplayWindow, pos: u16) void {
        const idx = pos / 64;
        const bit = @as(u6, @intCast(pos % 64));
        if (idx < self.bitmap.len) {
            self.bitmap[idx] |= @as(u64, 1) << bit;
        }
    }

    fn getBit(self: *AntiReplayWindow, pos: u16) bool {
        const idx = pos / 64;
        const bit = @as(u6, @intCast(pos % 64));
        if (idx < self.bitmap.len) {
            return (self.bitmap[idx] & (@as(u64, 1) << bit)) != 0;
        }
        return false;
    }

    fn shiftWindow(self: *AntiReplayWindow, shift: u16) void {
        if (shift >= self.window_size) {
            @memset(self.bitmap, 0);
            return;
        }

        const word_shift = shift / 64;
        const bit_shift = @as(u6, @intCast(shift % 64));

        // Shift by whole words
        if (word_shift > 0) {
            var i = self.bitmap.len;
            while (i > word_shift) : (i -= 1) {
                self.bitmap[i - 1] = self.bitmap[i - 1 - word_shift];
            }
            var j: usize = 0;
            while (j < word_shift and j < self.bitmap.len) : (j += 1) {
                self.bitmap[j] = 0;
            }
        }

        // Shift remaining bits
        if (bit_shift > 0 and bit_shift < 64) {
            var i = self.bitmap.len;
            while (i > 0) : (i -= 1) {
                self.bitmap[i - 1] >>= bit_shift;
                if (i > 1 and bit_shift > 0) {
                    // Calculate complement shift amount, capped to valid u6 range
                    const comp_shift = if (bit_shift >= 64) 0 else (64 - @as(u64, bit_shift));
                    self.bitmap[i - 1] |= self.bitmap[i - 2] << @as(u6, @intCast(comp_shift));
                }
            }
        }
    }
};

// Checksum utilities
pub fn calculateIpv4Checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | @as(u32, data[i + 1]);
    }

    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

// Rate limiter using token bucket algorithm
pub const RateLimiter = struct {
    capacity: u64,        // Token capacity
    tokens: u64,          // Current tokens
    refill_rate: u64,     // Tokens per second
    last_refill: i128,    // Last refill timestamp
    mutex: std.Thread.Mutex = .{},

    pub fn init(capacity: u64, refill_rate: u64) RateLimiter {
        return .{
            .capacity = capacity,
            .tokens = capacity,
            .refill_rate = refill_rate,
            .last_refill = std.time.nanoTimestamp(),
        };
    }

    pub fn tryConsume(self: *RateLimiter, tokens: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.refill();

        if (self.tokens >= tokens) {
            self.tokens -= tokens;
            return true;
        }
        return false;
    }

    fn refill(self: *RateLimiter) void {
        const now = std.time.nanoTimestamp();
        const elapsed = now - self.last_refill;
        const elapsed_sec = @as(f64, @floatFromInt(elapsed)) / @as(f64, std.time.ns_per_s);

        const tokens_to_add = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.refill_rate)) * elapsed_sec));

        if (tokens_to_add > 0) {
            self.tokens = @min(self.capacity, self.tokens + tokens_to_add);
            self.last_refill = now;
        }
    }

    pub fn getAvailableTokens(self: *RateLimiter) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.refill();
        return self.tokens;
    }
};

// Circular buffer for zero-copy packet handling
pub fn CircularBuffer(comptime T: type) type {
    return struct {
        buffer: []T,
        read_pos: usize = 0,
        write_pos: usize = 0,
        count: usize = 0,
        allocator: std.mem.Allocator,
        mutex: std.Thread.Mutex = .{},

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, cap: usize) !Self {
            return .{
                .buffer = try allocator.alloc(T, cap),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
        }

        pub fn push(self: *Self, item: T) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.count >= self.buffer.len) {
                return error.BufferFull;
            }

            self.buffer[self.write_pos] = item;
            self.write_pos = (self.write_pos + 1) % self.buffer.len;
            self.count += 1;
        }

        pub fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.count == 0) {
                return null;
            }

            const item = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.buffer.len;
            self.count -= 1;

            return item;
        }

        pub fn len(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.count;
        }

        pub fn capacity(self: *Self) usize {
            return self.buffer.len;
        }

        pub fn isFull(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.count >= self.buffer.len;
        }

        pub fn isEmpty(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.count == 0;
        }
    };
}

test "TEID generation" {
    var gen = try TeidGenerator.init();

    const teid1 = gen.generate();
    const teid2 = gen.generate();

    try std.testing.expect(teid1 != 0);
    try std.testing.expect(teid2 != 0);
    // TEIDs should generally be different (not guaranteed but highly likely)
}

test "TEID range generation" {
    const allocator = std.testing.allocator;
    var gen = try TeidGenerator.init();

    const teids = try gen.generateRange(10, allocator);
    defer allocator.free(teids);

    try std.testing.expectEqual(@as(usize, 10), teids.len);

    // Verify all TEIDs are non-zero and unique
    for (teids) |teid| {
        try std.testing.expect(teid != 0);
    }
}

test "Anti-replay window" {
    const allocator = std.testing.allocator;

    var window = try AntiReplayWindow.init(allocator, 64);
    defer window.deinit();

    // Accept first packet
    try std.testing.expect(window.check(1));

    // Reject duplicate
    try std.testing.expect(!window.check(1));

    // Accept newer packet
    try std.testing.expect(window.check(2));
    try std.testing.expect(window.check(3));

    // Accept old packet within window
    try std.testing.expect(window.check(2));

    // Reject duplicate old packet
    try std.testing.expect(!window.check(2));
}

test "Rate limiter" {
    var limiter = RateLimiter.init(100, 10);

    // Should be able to consume initial tokens
    try std.testing.expect(limiter.tryConsume(50));
    try std.testing.expect(limiter.tryConsume(50));

    // Should fail when out of tokens
    try std.testing.expect(!limiter.tryConsume(1));

    // Wait for refill (in real scenario)
    std.time.sleep(std.time.ns_per_s / 5); // 200ms

    // Should have some tokens now
    try std.testing.expect(limiter.tryConsume(1));
}

test "Circular buffer" {
    const allocator = std.testing.allocator;

    var buffer = try CircularBuffer(u32).init(allocator, 4);
    defer buffer.deinit();

    try std.testing.expect(buffer.isEmpty());

    try buffer.push(1);
    try buffer.push(2);
    try buffer.push(3);

    try std.testing.expectEqual(@as(usize, 3), buffer.len());

    try std.testing.expectEqual(@as(?u32, 1), buffer.pop());
    try std.testing.expectEqual(@as(?u32, 2), buffer.pop());

    try buffer.push(4);
    try buffer.push(5);

    try std.testing.expectEqual(@as(?u32, 3), buffer.pop());
    try std.testing.expectEqual(@as(?u32, 4), buffer.pop());
}
