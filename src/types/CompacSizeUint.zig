//! CompactSize Unsigned Integer
//!
//! A wrapper arround an `u64` exposing the en/decoding methods.
//!
//! * Specifications:
//! https://btcinformation.org/en/developer-reference#compactsize-unsigned-integers
//!
//! * Implementation details:
//! This implementation accounts for system endianness, and will work correctly on both big and little endian system.

const Self = @This();

const std = @import("std");
const io = std.io;
const native_endian = @import("builtin").target.cpu.arch.endian();

/// The inner value
inner: u64,

/// Returns a new instance
pub inline fn new(inner: u64) Self {
    return .{ .inner = inner };
}

/// Returns the original value
pub inline fn value(self: Self) u64 {
    return self.inner;
}

pub fn hint_encoded_len(self: Self) usize {
    const v = self.value();

    return if (v <= 252)
        1
    else if (v <= 0xffff)
        3
    else if (v <= 0xffffffff)
        5
    else
        9;
}

/// Encodes the inner value
///
/// The caller is responsible for freeing the returned memory.
pub fn encode(self: Self, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    const encoded_len = self.hint_encoded_len();
    const res = try allocator.alloc(u8, encoded_len);

    self.encodeToSlice(res);

    return res;
}

/// Encodes the inner value into a slice
///
/// dest.len must be >= self.hint_encoded_len().
pub fn encodeToSlice(self: Self, dest: []u8) void {
    const v = self.value();

    if (v <= 252) {
        std.mem.writeInt(u8, dest[0..1], @intCast(v), .little);
    } else if (v <= 0xffff) {
        dest[0] = 0xfd;
        std.mem.writeInt(u16, dest[1..3], @intCast(v), .little);
    } else if (v <= 0xffffffff) {
        dest[0] = 0xfe;
        std.mem.writeInt(u32, dest[1..5], @intCast(v), .little);
    } else {
        dest[0] = 0xff;
        std.mem.writeInt(u64, dest[1..9], @intCast(v), .little);
    }
}

/// Encodes the inner value into the writer
pub fn encodeToWriter(self: Self, w: anytype) !void {
    comptime {
        if (!std.meta.hasFn(@TypeOf(w), "writeByte")) @compileError("Expects w to have fn 'writeByte'.");
        if (!std.meta.hasFn(@TypeOf(w), "writeInt")) @compileError("Expects w to have fn 'writeInt'.");
    }

    const val = self.value();

    if (val <= 252) {
        try w.writeInt(u8, @intCast(val), .little);
    } else if (val <= 0xffff) {
        try w.writeByte(0xfd);
        try w.writeInt(u16, @intCast(val), .little);
    } else if (val <= 0xffffffff) {
        try w.writeByte(0xfe);
        try w.writeInt(u32, @intCast(val), .little);
    } else {
        try w.writeByte(0xff);
        try w.writeInt(u64, @intCast(val), .little);
    }
}

pub const DecodeCompactSizeUintError = error{
    EmptyInput,
    InputTooShort,
};

/// Parses an encoded u64 as a CompactSizeUint
pub fn decodeSlice(input: []const u8) DecodeCompactSizeUintError!Self {
    if (input.len == 0) return error.EmptyInput;

    const num_len: usize = switch (input[0]) {
        0xff => ff: {
            if (input.len < 9) return error.InputTooShort;
            break :ff 8;
        },
        0xfe => fe: {
            if (input.len < 5) return error.InputTooShort;
            break :fe 4;
        },
        0xfd => fd: {
            if (input.len < 3) return error.InputTooShort;
            break :fd 2;
        },
        else => return .{ .inner = input[0] },
    };

    var buffer = [_]u8{0} ** 8;
    @memcpy(buffer[0..num_len], input[1 .. num_len + 1]);
    if (native_endian == .big) {
        @byteSwap(buffer);
    }

    return .{ .inner = @bitCast(buffer) };
}

/// Parses an encoded u64 as a CompactSizeUint
pub fn decodeReader(r: anytype) !Self {
    comptime {
        if (!std.meta.hasFn(@TypeOf(r), "readByte")) @compileError("Expects r to have fn 'readByte'.");
        if (!std.meta.hasFn(@TypeOf(r), "readNoEof")) @compileError("Expects r to have fn 'readNoEof'.");
    }

    const first_byte = try r.readByte();
    const num_len: usize = switch (first_byte) {
        0xff => 8,
        0xfe => 4,
        0xfd => 2,
        else => return .{ .inner = @intCast(first_byte) },
    };

    var buffer = std.mem.zeroes([8]u8);
    try r.readNoEof(buffer[0..num_len]);
    if (native_endian == .big) {
        @byteSwap(buffer);
    }

    return .{ .inner = @bitCast(buffer) };
}

// TESTS

test "ok_full_flow_for_key_values" {
    const values = [_]u64{ 0, 252, 0xffff, 0xffffffff, std.math.maxInt(u64) };
    const zeroed_buffer = [_]u8{0} ** 9;
    var buffer = [_]u8{0} ** 9;
    const allocator = std.testing.allocator;

    for (values) |num| {
        const compact = Self.new(num);
        // encode
        {
            const encoding = try compact.encode(allocator);
            defer allocator.free(encoding);
            const decoded = try Self.decodeSlice(encoding);
            try std.testing.expectEqual(decoded.value(), num);
        }
        // encode_to_slice
        {
            @memcpy(buffer[0..], zeroed_buffer[0..]);
            const buf = buffer[9 - compact.hint_encoded_len() ..];
            compact.encodeToSlice(buf);
            const decoded = try Self.decodeSlice(buf);
            try std.testing.expectEqual(decoded.value(), num);
        }
        // encode_to_writer
        {
            @memcpy(buffer[0..], zeroed_buffer[0..]);
            var fbs = std.io.fixedBufferStream(&buffer);
            const writer = fbs.writer();
            const reader = fbs.reader();
            try compact.encodeToWriter(writer);
            fbs.reset();
            const decoded = try Self.decodeReader(reader);
            try std.testing.expectEqual(decoded.value(), num);
        }
    }
}

test "ok_full_flow_for_1k_random_values" {
    const rand = std.crypto.random;
    const zeroed_buffer = [_]u8{0} ** 9;
    var buffer = [_]u8{0} ** 9;
    const allocator = std.testing.allocator;

    for (0..1000) |_| {
        const num = rand.int(u64);

        const compact = Self.new(num);

        // encode
        {
            const encoding = try compact.encode(allocator);
            defer allocator.free(encoding);
            const decoded = try Self.decodeSlice(encoding);
            try std.testing.expectEqual(decoded.value(), num);
        }
        // encode_to_slice
        {
            @memcpy(buffer[0..], zeroed_buffer[0..]);
            const buf = buffer[9 - compact.hint_encoded_len() ..];
            compact.encodeToSlice(buf);
            const decoded = try Self.decodeSlice(buf);
            try std.testing.expectEqual(decoded.value(), num);
        }
        // encode_to_writer
        {
            @memcpy(buffer[0..], zeroed_buffer[0..]);
            var fbs = std.io.fixedBufferStream(&buffer);
            const writer = fbs.writer();
            const reader = fbs.reader();
            try compact.encodeToWriter(writer);
            fbs.reset();
            const decoded = try Self.decodeReader(reader);
            try std.testing.expectEqual(decoded.value(), num);
        }
    }
}

test "ko_decode_slice" {
    var input = [_]u8{0} ** 10;

    input[0] = 0xff;
    try std.testing.expectError(error.InputTooShort, Self.decodeSlice(input[0..8]));
    _ = try Self.decodeSlice(input[0..9]);
    _ = try Self.decodeSlice(input[0..]);

    input[0] = 0xfe;
    try std.testing.expectError(error.InputTooShort, Self.decodeSlice(input[0..4]));
    _ = try Self.decodeSlice(input[0..5]);
    _ = try Self.decodeSlice(input[0..]);

    input[0] = 0xfd;
    try std.testing.expectError(error.InputTooShort, Self.decodeSlice(input[0..2]));
    _ = try Self.decodeSlice(input[0..3]);
    _ = try Self.decodeSlice(input[0..]);

    input[0] = 0xfc;
    try std.testing.expectError(error.EmptyInput, Self.decodeSlice(input[0..0]));
    _ = try Self.decodeSlice(input[0..1]);
    _ = try Self.decodeSlice(input[0..]);
}

test "ko_endode_when_oom" {
    const allocator = std.testing.failing_allocator;

    const num = Self.new(42);

    try std.testing.expectError(error.OutOfMemory, num.encode(allocator));
}
