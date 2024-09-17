const std = @import("std");
const testing = std.testing;
const sha256 = std.crypto.hash.sha256;
const Ripemd160 = @import("ripemd160.zig").Ripemd160;

pub const Hash160 = struct {
    const Self = @This();
    pub const digest_length = 20;
    pub const Options = struct {};

    pub fn init(_: Options) Self {
        return .{};
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, _: Options) void {
        var sha_out: [32]u8 = undefined;
        var ripemd_out: [digest_length]u8 = undefined;

        // Step 1: Compute SHA256 hash
        var sha = sha256.init();
        sha.update(b);
        sha.final(&sha_out);

        // Step 2: Compute RIPEMD160 of the SHA256 result
        Ripemd160.hash(&sha_out, &ripemd_out, .{});

        // Copy the RIPEMD160 result to the output
        @memcpy(out, &ripemd_out);
    }
};

// Testing Hash160 against known vectors
test "hash160 vectors" {
    const input = [_][]const u8{
        "abc",
        "bitcoin",
        "lorem ipsum",
        "we do a lil hashing",
    };

    const output = [_][]const u8{
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "5891bf40b0b0e8e19f524bdc2e842d012264624b",
        "b3a8cd8a27c90af79b3c81754f267780f443dfef",
        "8fb8d7be38d54b1580299632f957dfeba9eb55f3",
    };

    for (0..input.len) |i| {
        var expected_output: [Hash160.digest_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_output, output[i]);
        var actual_output: [Hash160.digest_length]u8 = undefined;
        Hash160.hash(input[i], &actual_output, .{});
        try testing.expectEqualSlices(u8, &expected_output, &actual_output);
    }
}
