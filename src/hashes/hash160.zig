const std = @import("std");
const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ripemd160 = @import("ripemd160.zig").Ripemd160;

pub const Hash160 = struct {
    const Self = @This();
    pub const digest_length = 20;
    pub const Options = struct {};

    pub fn init(_: Options) Self {
        return .{};
    }

    pub inline fn hash(b: []const u8, out: *[digest_length]u8, _: Options) void {
        var sha_out: [Sha256.digest_length]u8 = undefined;

        // Step 1: Compute SHA256 hash
        Sha256.hash(b, &sha_out, .{});

        // Step 2: Compute RIPEMD160 of the SHA256 result
        Ripemd160.hash(&sha_out, out, .{});
    }
};

// Testing Hash160 against known vectors
test "hash160 vectors" {
    const test_cases = [_]struct {
        input: []const u8,
        expected: []const u8,
    }{
        .{ .input = "hello", .expected = "b6a9c8c230722b7c748331a8b450f05566dc7d0f" },
        .{ .input = "blockchain", .expected = "755f6f4af6e11c5cf642f0ed6ecda89d8619cee7" },
        .{ .input = "abc", .expected = "bb1be98c142444d7a56aa3981c3942a978e4dc33" },
        .{ .input = "bitcoin", .expected = "6b2904910f9b40b2244eed93a7b8d992b22f8d32" },
    };

    for (test_cases) |case| {
        errdefer {
            std.log.err("test case failed, case = {s}", .{std.json.fmt(case, .{})});
        }
        var expected_output: [Hash160.digest_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_output, case.expected);

        var actual_output: [Hash160.digest_length]u8 = undefined;

        Hash160.hash(case.input, &actual_output, .{});
        try testing.expectEqualSlices(u8, &expected_output, &actual_output);
    }
}
