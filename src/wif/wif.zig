const PrivateKey = @import("../bips/bip32/key.zig").PrivateKey;
const Network = @import("../bips/bip32/bip32.zig").Network;
const std = @import("std");
const Base58Encoder = @import("../base58/base58.zig").Encoder;
const Base58Decoder = @import("../base58/base58.zig").Decoder;
const secp256k1 = @import("secp256k1");

/// WIF as defined in https://en.bitcoin.it/wiki/Wallet_import_format
pub const WIF_PREFIX_MAINNET: u8 = 0x80;
pub const WIF_PREFIX_TESTNET: u8 = 0xef;
pub const WIF_COMPRESSED_FLAG: u8 = 0x01;

pub const WIFDecodeError = error{ InvalidNetwork, InvalidChecksum };

pub const WIF = struct {
    const Self = @This();
    inner: []u8,

    pub fn fromPrivateKey(private_key: PrivateKey) !Self {
        const max_size = 1 + 32 + 1 + 4; // prefix + key  + compressed flag + checksum
        var actual_size: u8 = max_size - 1;
        if (private_key.compressed) {
            actual_size += 1;
        }
        var buf = [_]u8{0} ** max_size;

        if (private_key.network == Network.MAINNET) {
            buf[0] = WIF_PREFIX_MAINNET;
        } else {
            buf[0] = WIF_PREFIX_TESTNET;
        }

        @memcpy(buf[1..33], private_key.inner.data[0..32]);

        if (private_key.compressed) {
            buf[33] = WIF_COMPRESSED_FLAG;
        }

        var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
        var out256: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;

        sha256.update(buf[0 .. actual_size - 4]);
        sha256.final(&out256);

        sha256 = std.crypto.hash.sha2.Sha256.init(.{});

        sha256.update(out256[0..std.crypto.hash.sha2.Sha256.digest_length]);
        sha256.final(&out256);

        @memcpy(buf[actual_size - 4 .. actual_size], out256[0..4]);

        // base58 encode
        const encoder = Base58Encoder{};
        var encode_buf = [_]u8{0} ** 52; // max wif len is 52
        const encode_size = encoder.encode(buf[0..actual_size], &encode_buf);
        const wif = WIF{
            .inner = encode_buf[0..encode_size],
        };
        return wif;
    }

    pub fn toString(self: WIF) []u8 {
        return self.inner;
    }

    pub fn fromString(wif: []const u8) !WIF {
        // decode base58
        const decoder = Base58Decoder{};

        var decoded = [_]u8{0} ** 38; // max len is 38
        const decode_size = try decoder.decode(wif, &decoded);

        const new_wif = WIF{
            .inner = decoded[0..decode_size],
        };

        // check checksum
        var out256: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;

        var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
        sha256.update(decoded[0 .. decode_size - 4]);
        sha256.final(&out256);

        sha256 = std.crypto.hash.sha2.Sha256.init(.{});

        sha256.update(out256[0..std.crypto.hash.sha2.Sha256.digest_length]);
        sha256.final(&out256);

        if (decoded[decode_size - 4] != out256[0] or
            decoded[decode_size - 3] != out256[1] or
            decoded[decode_size - 2] != out256[2] or
            decoded[decode_size - 1] != out256[3])
        {
            return WIFDecodeError.InvalidChecksum;
        }

        return new_wif;
    }

    pub fn toPrivateKey(self: WIF) !PrivateKey {
        const network = switch (self.inner[0]) {
            WIF_PREFIX_MAINNET => Network.MAINNET,
            WIF_PREFIX_TESTNET => Network.TESTNET,
            else => return WIFDecodeError.InvalidNetwork,
        };
        const compressed = self.inner[33] == WIF_COMPRESSED_FLAG;

        const data: [32]u8 = self.inner[1..33].*; // secp256k1.SecretKey.fromSlice has some weird effect on the array
        return PrivateKey{ .network = network, .compressed = compressed, .inner = try secp256k1.SecretKey.fromSlice(&data) };
    }
};

test "WIF with compressed private key" {
    const privateKey = PrivateKey{ .network = Network.MAINNET, .compressed = true, .inner = try secp256k1.SecretKey.fromString("7bea4d472aa93e49321bbde5db88b126b9435482e1f39d84664530a5f40408cd") };
    const wif = try WIF.fromPrivateKey(privateKey);
    const expected = "L1NawHPsZVHsnW4DUBC7K36LzXfcsLck85fMSoEGyT4LMZv9xSjD";
    const actual = wif.toString();
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);

    const got_wif = try WIF.fromString(expected);
    const got_privateKey = try got_wif.toPrivateKey();
    try std.testing.expectEqualDeep(privateKey, got_privateKey);
}

test "WIF with uncompressed private key 2" {
    const privateKey = PrivateKey{ .network = Network.MAINNET, .compressed = false, .inner = try secp256k1.SecretKey.fromString("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D") };
    const wif = try WIF.fromPrivateKey(privateKey);
    const expected = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const actual = wif.toString();
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);

    const got_wif = try WIF.fromString(expected);
    const got_privateKey = try got_wif.toPrivateKey();
    try std.testing.expectEqualDeep(privateKey, got_privateKey);
}

test "WIF with uncompressed private key" {
    const privateKey = PrivateKey{ .network = Network.MAINNET, .compressed = false, .inner = try secp256k1.SecretKey.fromString("46605abb568e1566834e7ee57e271964534d8fc3b23ca5f546b081ad7e233671") };
    const wif = try WIF.fromPrivateKey(privateKey);
    const expected = "5JMHFZHuMcVnqVBARmg3jW3LMxdB6qbJtesC5xhXRji6wabvbWu";
    const actual = wif.toString();
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);

    const got_wif = try WIF.fromString(expected);
    const got_privateKey = try got_wif.toPrivateKey();
    try std.testing.expectEqualDeep(privateKey, got_privateKey);
}

test "WIF with compressed testnet private key" {
    const privateKey = PrivateKey{ .network = Network.TESTNET, .compressed = true, .inner = try secp256k1.SecretKey.fromString("46605abb568e1566834e7ee57e271964534d8fc3b23ca5f546b081ad7e233671") };
    const wif = try WIF.fromPrivateKey(privateKey);
    const expected = "cPwWCAXTX3NLUSq7zjzURugN5jp5FDa832H13KJNoJARUPsaTJ9G";
    const actual = wif.toString();
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);

    const got_wif = try WIF.fromString(expected);
    const got_privateKey = try got_wif.toPrivateKey();
    try std.testing.expectEqualDeep(privateKey, got_privateKey);
}

test "WIF with uncompressed testnet private key\n" {
    const privateKey = PrivateKey{ .network = Network.TESTNET, .compressed = false, .inner = try secp256k1.SecretKey.fromString("46605abb568e1566834e7ee57e271964534d8fc3b23ca5f546b081ad7e233671") };
    const wif = try WIF.fromPrivateKey(privateKey);
    const expected = "927uqJ7SwqZvoYgT47Zxc6bJ1cytG18WEbj9Ab42mUT9icaLVhF";
    const actual = wif.toString();
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);

    const got_wif = try WIF.fromString(expected);
    const got_privateKey = try got_wif.toPrivateKey();
    try std.testing.expectEqualDeep(privateKey, got_privateKey);
}
