const std = @import("std");
const Hash = std.crypto.sha256;

pub const HashEngine = struct {
    sha256_engine: Hash.Context,

    pub fn new() HashEngine {
        return HashEngine{
            .sha256_engine = Hash.Context.init(),
        };
    }

    pub fn input(self: *HashEngine, data: []const u8) void {
        self.sha256_engine.update(data);
    }

    pub fn n_bytes_hashed(self: *const HashEngine) usize {
        return self.sha256_engine.total_len;
    }

    pub fn final(self: *HashEngine) []u8 {
        var sha1_result: [32]u8 = undefined;
        self.sha256_engine.final(&sha1_result);

        var sha2_result: [32]u8 = undefined;
        var second_sha256 = Hash.hash(sha1_result[0..]);
        std.mem.copy(u8, sha2_result[0..], second_sha256[0..]);

        return sha2_result[0..];
    }
};

// Test cases
test "double SHA256 (SHA256d)" {
    const input = "hello world";
    var engine = HashEngine.new();
    engine.input(input);

    const expected_hash: [32]u8 = [_]u8{ 0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x6e, 0x0f, 0xf4, 0x78, 0x91, 0x87, 0x3c, 0xc8, 0x89, 0x3f, 0xbe, 0x58, 0x68, 0xb2, 0x38 };

    const result = engine.final();

    try std.testing.expect(std.mem.eql(u8, result, expected_hash));
}

test "empty string double SHA256 (SHA256d)" {
    const input = "";
    var engine = HashEngine.new();
    engine.input(input);

    const expected_hash: [32]u8 = [_]u8{ 0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56 };

    const result = engine.final();

    try std.testing.expect(std.mem.eql(u8, result, expected_hash));
}
