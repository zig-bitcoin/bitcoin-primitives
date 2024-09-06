const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const testing = std.testing;

pub fn Tag(comptime tag_value: []const u8) type {
    return struct {
        pub fn engine() Sha256 {
            var h = Sha256.init(.{});
            h.update(tag_value);
            return h;
        }
    };
}

pub fn Hash(comptime T: type) type {
    return struct {
        bytes: [32]u8,

        const Self = @This();

        pub fn init(data: []const u8) Self {
            var h = T.engine();
            h.update(data);
            var out: [32]u8 = undefined;
            h.final(&out);
            return Self{ .bytes = out };
        }

        pub fn toSlice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        pub fn toString(self: *const Self) ![64]u8 {
            var buf: [64]u8 = undefined;
            _ = try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
            return buf;
        }
    };
}

pub fn Sha256t(comptime tag: []const u8) type {
    const TagType = Tag(tag);
    return Hash(TagType);
}

test "TestHash" {
    var h = Sha256.init(.{});
    var out: [32]u8 = undefined;

    h.final(out[0..]);
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };

    try testing.expectEqualSlices(u8, &expected, &out);
}
