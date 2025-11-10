// Memory Pool for High-Performance Packet Processing
// Zero-copy and batch processing support

const std = @import("std");

// Memory pool for fixed-size allocations
pub fn MemoryPool(comptime T: type) type {
    return struct {
        pool: []T,
        free_list: []?*T,
        free_count: usize,
        allocator: std.mem.Allocator,
        mutex: std.Thread.Mutex = .{},

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, cap: usize) !Self {
            const pool = try allocator.alloc(T, cap);
            errdefer allocator.free(pool);

            const free_list = try allocator.alloc(?*T, cap);
            errdefer allocator.free(free_list);

            // Initialize free list
            for (pool, 0..) |*item, i| {
                free_list[i] = item;
            }

            return .{
                .pool = pool,
                .free_list = free_list,
                .free_count = cap,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.free_list);
            self.allocator.free(self.pool);
        }

        pub fn acquire(self: *Self) ?*T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.free_count == 0) {
                return null;
            }

            self.free_count -= 1;
            const item = self.free_list[self.free_count];
            return item;
        }

        pub fn release(self: *Self, item: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Verify item belongs to pool
            const pool_start = @intFromPtr(&self.pool[0]);
            const pool_end = @intFromPtr(&self.pool[self.pool.len - 1]) + @sizeOf(T);
            const item_ptr = @intFromPtr(item);

            if (item_ptr < pool_start or item_ptr >= pool_end) {
                // Item doesn't belong to this pool
                return;
            }

            if (self.free_count < self.free_list.len) {
                self.free_list[self.free_count] = item;
                self.free_count += 1;
            }
        }

        pub fn available(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.free_count;
        }

        pub fn capacity(self: *Self) usize {
            return self.pool.len;
        }

        pub fn utilizationPercent(self: *Self) f64 {
            self.mutex.lock();
            defer self.mutex.unlock();

            const used = self.pool.len - self.free_count;
            return @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(self.pool.len)) * 100.0;
        }
    };
}

// Packet buffer for zero-copy operations
pub const PacketBuffer = struct {
    data: []u8,
    length: usize,
    capacity: usize,
    refs: std.atomic.Value(u32),

    pub fn init(data: []u8) PacketBuffer {
        return .{
            .data = data,
            .length = 0,
            .capacity = data.len,
            .refs = std.atomic.Value(u32).init(1),
        };
    }

    pub fn getData(self: *PacketBuffer) []u8 {
        return self.data[0..self.length];
    }

    pub fn setLength(self: *PacketBuffer, length: usize) void {
        self.length = @min(length, self.capacity);
    }

    pub fn addRef(self: *PacketBuffer) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *PacketBuffer) u32 {
        return self.refs.fetchSub(1, .monotonic) - 1;
    }

    pub fn getRefCount(self: *PacketBuffer) u32 {
        return self.refs.load(.monotonic);
    }
};

// Packet buffer pool
pub const PacketBufferPool = struct {
    pool: MemoryPool(PacketBuffer),
    buffer_size: usize,
    backing_memory: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, num_buffers: usize, buffer_size: usize) !PacketBufferPool {
        const backing_memory = try allocator.alloc(u8, num_buffers * buffer_size);
        errdefer allocator.free(backing_memory);

        var pool = try MemoryPool(PacketBuffer).init(allocator, num_buffers);
        errdefer pool.deinit();

        // Initialize each packet buffer
        for (0..num_buffers) |i| {
            const start = i * buffer_size;
            const end = start + buffer_size;
            pool.pool[i] = PacketBuffer.init(backing_memory[start..end]);
        }

        return .{
            .pool = pool,
            .buffer_size = buffer_size,
            .backing_memory = backing_memory,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PacketBufferPool) void {
        self.pool.deinit();
        self.allocator.free(self.backing_memory);
    }

    pub fn acquire(self: *PacketBufferPool) ?*PacketBuffer {
        if (self.pool.acquire()) |buf| {
            buf.length = 0;
            buf.refs.store(1, .monotonic);
            return buf;
        }
        return null;
    }

    pub fn release(self: *PacketBufferPool, buf: *PacketBuffer) void {
        const refs = buf.release();
        if (refs == 0) {
            self.pool.release(buf);
        }
    }

    pub fn available(self: *PacketBufferPool) usize {
        return self.pool.available();
    }
};

// Batch processor for packet batching
pub const BatchProcessor = struct {
    batch: []?*PacketBuffer,
    batch_size: usize,
    current_index: usize,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, max_batch_size: usize) !BatchProcessor {
        const batch = try allocator.alloc(?*PacketBuffer, max_batch_size);
        @memset(batch, null);

        return .{
            .batch = batch,
            .batch_size = 0,
            .current_index = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BatchProcessor) void {
        self.allocator.free(self.batch);
    }

    pub fn add(self: *BatchProcessor, packet: *PacketBuffer) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.batch_size >= self.batch.len) {
            return false;
        }

        self.batch[self.batch_size] = packet;
        self.batch_size += 1;
        return true;
    }

    pub fn process(self: *BatchProcessor, callback: *const fn (*PacketBuffer) void) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.batch[0..self.batch_size]) |maybe_packet| {
            if (maybe_packet) |packet| {
                callback(packet);
            }
        }

        // Reset batch
        @memset(self.batch, null);
        self.batch_size = 0;
    }

    pub fn clear(self: *BatchProcessor) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        @memset(self.batch, null);
        self.batch_size = 0;
    }

    pub fn size(self: *BatchProcessor) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.batch_size;
    }

    pub fn isFull(self: *BatchProcessor) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.batch_size >= self.batch.len;
    }
};

// Zero-copy buffer slice
pub const BufferSlice = struct {
    buffer: *PacketBuffer,
    offset: usize,
    length: usize,

    pub fn init(buffer: *PacketBuffer, offset: usize, length: usize) BufferSlice {
        buffer.addRef();
        return .{
            .buffer = buffer,
            .offset = offset,
            .length = length,
        };
    }

    pub fn deinit(self: *BufferSlice, pool: *PacketBufferPool) void {
        pool.release(self.buffer);
    }

    pub fn getData(self: BufferSlice) []u8 {
        const end = @min(self.offset + self.length, self.buffer.length);
        return self.buffer.data[self.offset..end];
    }
};

test "MemoryPool basic operations" {
    const allocator = std.testing.allocator;

    var pool = try MemoryPool(u64).init(allocator, 10);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 10), pool.capacity());
    try std.testing.expectEqual(@as(usize, 10), pool.available());

    const item1 = pool.acquire();
    try std.testing.expect(item1 != null);
    try std.testing.expectEqual(@as(usize, 9), pool.available());

    const item2 = pool.acquire();
    try std.testing.expect(item2 != null);
    try std.testing.expectEqual(@as(usize, 8), pool.available());

    pool.release(item1.?);
    try std.testing.expectEqual(@as(usize, 9), pool.available());

    pool.release(item2.?);
    try std.testing.expectEqual(@as(usize, 10), pool.available());
}

test "PacketBufferPool" {
    const allocator = std.testing.allocator;

    var pool = try PacketBufferPool.init(allocator, 5, 1024);
    defer pool.deinit();

    const buf1 = pool.acquire();
    try std.testing.expect(buf1 != null);
    try std.testing.expectEqual(@as(usize, 1024), buf1.?.capacity);

    buf1.?.setLength(100);
    try std.testing.expectEqual(@as(usize, 100), buf1.?.length);

    pool.release(buf1.?);
    try std.testing.expectEqual(@as(usize, 5), pool.available());
}

test "PacketBuffer reference counting" {
    const allocator = std.testing.allocator;

    var pool = try PacketBufferPool.init(allocator, 1, 1024);
    defer pool.deinit();

    const buf = pool.acquire().?;
    try std.testing.expectEqual(@as(u32, 1), buf.getRefCount());

    buf.addRef();
    try std.testing.expectEqual(@as(u32, 2), buf.getRefCount());

    pool.release(buf);
    try std.testing.expectEqual(@as(u32, 1), buf.getRefCount());
    try std.testing.expectEqual(@as(usize, 0), pool.available());

    pool.release(buf);
    try std.testing.expectEqual(@as(usize, 1), pool.available());
}

test "BatchProcessor" {
    const allocator = std.testing.allocator;

    var processor = try BatchProcessor.init(allocator, 10);
    defer processor.deinit();

    var pool = try PacketBufferPool.init(allocator, 10, 1024);
    defer pool.deinit();

    const buf1 = pool.acquire().?;
    const buf2 = pool.acquire().?;

    try std.testing.expect(processor.add(buf1));
    try std.testing.expect(processor.add(buf2));
    try std.testing.expectEqual(@as(usize, 2), processor.size());

    _ = 0; // var processed: usize = 0;
    const callback = struct {
        fn call(packet: *PacketBuffer) void {
            _ = packet;
            // Would process packet here
        }
    }.call;

    processor.process(callback);
    try std.testing.expectEqual(@as(usize, 0), processor.size());

    pool.release(buf1);
    pool.release(buf2);
}
