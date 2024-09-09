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

/// Encodes the inner value
pub fn encode(self: Self, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    const small_endian_value: [8]u8 = @bitCast(self.value());
    switch (native_endian) {
        .little => {},
        .big => {
            std.mem.reverse([8]u8, small_endian_value);
        },
    }

    const v = self.value();
    if (v <= 252) {
        const res = try allocator.alloc(u8, 1);
        res[0] = small_endian_value[0];
        return res;
    } else if (v <= 0xffff) {
        const res = try allocator.alloc(u8, 3);
        res[0] = 0xfd;
        std.mem.copyForwards(u8, res[1..], small_endian_value[0..2]);
        return res;
    } else if (v <= 0xffffffff) {
        const res = try allocator.alloc(u8, 5);
        res[0] = 0xfe;
        std.mem.copyForwards(u8, res[1..], small_endian_value[0..4]);
        return res;
    } else {
        const res = try allocator.alloc(u8, 9);
        res[0] = 0xff;
        std.mem.copyForwards(u8, res[1..], small_endian_value[0..]);
        return res;
    }
}

pub const DecodeSelfError = error{
    EmptyInput,
    InputTooLong,
    InvalidInputLengthForPrefix,
};

/// Parses an encoded u64 as a CompactSizeUint
///
/// Input length should be between 1 and 9, correctly prefixed.
pub fn decode(input: []const u8) DecodeSelfError!Self {
    if (input.len == 0) return error.EmptyInput;
    if (input.len > 9) return error.InputTooLong;

    const start: usize = switch (input[0]) {
        0xff => ff: {
            if (input.len != 9) return error.InvalidInputLengthForPrefix;
            break :ff 1;
        },
        0xfe => fe: {
            if (input.len != 5) return error.InvalidInputLengthForPrefix;
            break :fe 1;
        },
        0xfd => fd: {
            if (input.len != 3) return error.InvalidInputLengthForPrefix;
            break :fd 1;
        },
        else => _: {
            if (input.len != 1) return error.InvalidInputLengthForPrefix;
            break :_ 0;
        },
    };

    var buffer = [_]u8{0} ** 8;
    std.mem.copyForwards(u8, &buffer, input[start..]);
    switch (native_endian) {
        .little => {},
        .big => {
            std.mem.reverse([8]u8, buffer);
        },
    }
    return .{ .inner = @bitCast(buffer) };
}

// TESTS

test "ok_full_flow_for_key_values" {
    const values = [_]u64{ 0, 252, 0xffff, 0xffffffff, std.math.maxInt(u64) };

    for (values) |num| {
        const allocator = std.testing.allocator;

        const compact = Self.new(num);
        const encoding = try compact.encode(allocator);
        defer allocator.free(encoding);
        const decoded = try Self.decode(encoding);
        try std.testing.expectEqual(decoded.value(), num);
    }
}

test "ok_full_flow_for_1k_random_values" {
    const rand = std.crypto.random;

    for (0..1000) |_| {
        const allocator = std.testing.allocator;
        const num = rand.int(u64);

        const compact = Self.new(num);
        const encoding = try compact.encode(allocator);
        defer allocator.free(encoding);
        const decoded = try Self.decode(encoding);
        try std.testing.expectEqual(decoded.value(), num);
    }
}

test "ko_decode" {
    var input = [_]u8{0} ** 10;

    input[0] = 0xff;
    try std.testing.expectError(error.InvalidInputLengthForPrefix, Self.decode(input[0..8]));
    _ = try Self.decode(input[0..9]);
    try std.testing.expectError(error.InputTooLong, Self.decode(input[0..10]));

    input[0] = 0xfe;
    try std.testing.expectError(error.InvalidInputLengthForPrefix, Self.decode(input[0..4]));
    _ = try Self.decode(input[0..5]);
    try std.testing.expectError(error.InvalidInputLengthForPrefix, Self.decode(input[0..6]));

    input[0] = 0xfd;
    try std.testing.expectError(error.InvalidInputLengthForPrefix, Self.decode(input[0..2]));
    _ = try Self.decode(input[0..3]);
    try std.testing.expectError(error.InvalidInputLengthForPrefix, Self.decode(input[0..4]));

    input[0] = 0xfc;
    try std.testing.expectError(error.EmptyInput, Self.decode(input[0..0]));
    _ = try Self.decode(input[0..1]);
    try std.testing.expectError(error.InvalidInputLengthForPrefix, Self.decode(input[0..2]));
}

test "ko_endode_when_oom" {
    const allocator = std.testing.failing_allocator;

    const num = Self.new(42);

    try std.testing.expectError(error.OutOfMemory, num.encode(allocator));
}
