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

    self.encode_to(res);

    return res;
}

/// Encodes the inner value into a destination
///
/// dest.len must be >= self.hint_encoded_len().
pub fn encode_to(self: Self, dest: []u8) void {
    const small_endian_value: [8]u8 = @bitCast(self.value());
    switch (native_endian) {
        .little => {},
        .big => {
            std.mem.reverse(u8, small_endian_value);
        },
    }

    const v = self.value();
    if (v <= 252) {
        dest[0] = small_endian_value[0];
    } else if (v <= 0xffff) {
        dest[0] = 0xfd;
        @memcpy(dest[1..3], small_endian_value[0..2]);
    } else if (v <= 0xffffffff) {
        dest[0] = 0xfe;
        @memcpy(dest[1..5], small_endian_value[0..4]);
    } else {
        dest[0] = 0xff;
        @memcpy(dest[1..9], small_endian_value[0..]);
    }
}

pub const DecodeSelfError = error{
    EmptyInput,
    InputTooShort,
};

/// Parses an encoded u64 as a CompactSizeUint
///
/// Input length should be between 1 and 9, correctly prefixed.
pub fn decode(input: []const u8) DecodeSelfError!Self {
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
        else => _: {
            break :_ 1;
        },
    };
    const num_start: usize = if (num_len == 1) 0 else 1;

    var buffer = [_]u8{0} ** 8;
    @memcpy(buffer[0..num_len], input[num_start .. num_start + num_len]);
    switch (native_endian) {
        .little => {},
        .big => {
            std.mem.reverse(u8, buffer);
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
    var buffer = [_]u8{0} ** 9;

    for (0..1000) |_| {
        const allocator = std.testing.allocator;
        const num = rand.int(u64);

        const compact = Self.new(num);

        // encode
        {
            const encoding = try compact.encode(allocator);
            defer allocator.free(encoding);
            const decoded = try Self.decode(encoding);
            try std.testing.expectEqual(decoded.value(), num);
        }
        // encode_to
        {
            const buf = buffer[9 - compact.hint_encoded_len() ..];
            compact.encode_to(buf);
            const decoded = try Self.decode(buf);
            try std.testing.expectEqual(decoded.value(), num);
        }
    }
}

test "ko_decode" {
    var input = [_]u8{0} ** 10;

    input[0] = 0xff;
    try std.testing.expectError(error.InputTooShort, Self.decode(input[0..8]));
    _ = try Self.decode(input[0..9]);
    _ = try Self.decode(input[0..]);

    input[0] = 0xfe;
    try std.testing.expectError(error.InputTooShort, Self.decode(input[0..4]));
    _ = try Self.decode(input[0..5]);
    _ = try Self.decode(input[0..]);

    input[0] = 0xfd;
    try std.testing.expectError(error.InputTooShort, Self.decode(input[0..2]));
    _ = try Self.decode(input[0..3]);
    _ = try Self.decode(input[0..]);

    input[0] = 0xfc;
    try std.testing.expectError(error.EmptyInput, Self.decode(input[0..0]));
    _ = try Self.decode(input[0..1]);
    _ = try Self.decode(input[0..]);
}

test "ko_endode_when_oom" {
    const allocator = std.testing.failing_allocator;

    const num = Self.new(42);

    try std.testing.expectError(error.OutOfMemory, num.encode(allocator));
}
