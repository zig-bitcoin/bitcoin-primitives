const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Hmac = std.crypto.auth.hmac.Hmac;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn HKDF(comptime Hash: type) type {
    return struct {
        const Self = @This();
        pub const MAX_OUTPUT_BLOCKS = 255;

        prk: Hmac(Hash),

        pub fn init(salt: []const u8, ikm: []const u8) Self {
            var hmac = Hmac(Hash).init(salt);
            hmac.update(ikm);
            return Self{
                .prk = hmac,
            };
        }

        pub fn expand(self: *Self, info: []const u8, okm: []u8) !void {

            if (okm.len > MAX_OUTPUT_BLOCKS * Hash.digest_length) {
                return error.OutputTooLong;
            }

            var t = [_]u8{0} ** Hash.digest_length;
            var counter: u8 = 1;
            var pos: usize = 0;

            while (pos < okm.len) {
                var hmac = try Hmac(Hash).init(self.prk.key);

                if (pos > 0) {
                    hmac.update(&t);
                }
                hmac.update(info);
                hmac.update(&[_]u8{counter});
                hmac.final(&t);

                const remaining = okm.len - pos;
                const to_copy = @min(remaining, Hash.digest_length);
                mem.copy(u8, okm[pos..], t[0..to_copy]);

                pos += to_copy;
                counter += 1;
            }
        }

        pub fn expand_to_len(self: *Self, allocator: Allocator, info: []const u8, output_len: usize) ![]u8 {
            const okm = try allocator.alloc(u8, output_len);
            errdefer allocator.free(okm);

            try self.expand(info, okm);
            return okm;
        }
    };
}

fn hexToBytes(allocator: Allocator, hex: []const u8) ![]u8 {
    var bytes = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        bytes[i / 2] = try std.fmt.parseInt(u8, hex[i..i+2], 16);
    }
    return bytes;
}

fn bytesToHex(bytes: []const u8) ![]u8 {
    const hex = try testing.allocator.alloc(u8, bytes.len * 2);
    defer testing.allocator.free(hex);
    _ = try std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(bytes)});
    return hex;
}

test "HKDF test vectors" {
    const HkdfSha256 = HKDF(Sha256);

    // Test case 1: Basic test vector
    {
        const salt = try hexToBytes(testing.allocator, "000102030405060708090a0b0c");
        defer testing.allocator.free(salt);
        const ikm = try hexToBytes(testing.allocator, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        defer testing.allocator.free(ikm);
        const info = try hexToBytes(testing.allocator, "f0f1f2f3f4f5f6f7f8f9");
        defer testing.allocator.free(info);

        var hkdf = HkdfSha256.init(salt, ikm);
        const okm = try hkdf.expand_to_len(testing.allocator, info, 42);
        defer testing.allocator.free(okm);

        const expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        try testing.expectEqualStrings(expected, try bytesToHex(okm));
    }

    // Test case 2: Longer inputs and outputs
    {
        const salt = try hexToBytes(testing.allocator, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        defer testing.allocator.free(salt);
        const ikm = try hexToBytes(testing.allocator, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        defer testing.allocator.free(ikm);
        const info = try hexToBytes(testing.allocator, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        defer testing.allocator.free(info);

        var hkdf = HkdfSha256.init(salt, ikm);
        const okm = try hkdf.expand_to_len(testing.allocator, info, 82);
        defer testing.allocator.free(okm);

        const expected = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";
        try testing.expectEqualStrings(expected, try bytesToHex(okm));
    }

    // Test case 3: Too long OKM
    {
        const salt = try hexToBytes(testing.allocator, "000102030405060708090a0b0c");
        defer testing.allocator.free(salt);
        const ikm = try hexToBytes(testing.allocator, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        defer testing.allocator.free(ikm);
        const info = try hexToBytes(testing.allocator, "f0f1f2f3f4f5f6f7f8f9");
        defer testing.allocator.free(info);

        var hkdf = HkdfSha256.init(salt, ikm);
        const result = hkdf.expand_to_len(testing.allocator, info, 256 * 32);
        try testing.expectError(error.OutputTooLong, result);
    }

    // Test case 4: Short OKM
    {
        const salt = try hexToBytes(testing.allocator, "000102030405060708090a0b0c");
        defer testing.allocator.free(salt);
        const ikm = try hexToBytes(testing.allocator, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        defer testing.allocator.free(ikm);
        const info = try hexToBytes(testing.allocator, "f0f1f2f3f4f5f6f7f8f9");
        defer testing.allocator.free(info);

        var hkdf = HkdfSha256.init(salt, ikm);
        const okm = try hkdf.expand_to_len(testing.allocator, info, 1);
        defer testing.allocator.free(okm);

        try testing.expectEqualStrings("3c", try bytesToHex(okm));
    }
}
