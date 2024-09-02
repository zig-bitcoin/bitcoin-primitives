const std = @import("std");
const expectEqualSlices = std.testing.expectEqualSlices;

pub const Alphabet = struct {
    const Self = @This();

    /// Alphabet for base58 encoding and decoding.
    ///
    /// Bitcoin alphabet is used by default.
    ///
    /// Bitcoin's alphabet as defined in their Base58Check encoding.
    ///
    /// See <https://en.bitcoin.it/wiki/Base58Check_encoding#Base58_symbol_chart>
    encode: [58]u8 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".*,

    /// Initialize the alphabet to Bitcoin's alphabet.
    pub fn initBitcoin() Self {
        return .{};
    }
};

test "Alphabet: verify Bitcoin alphabet" {
    try expectEqualSlices(
        u8,
        &"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".*,
        &Alphabet.initBitcoin().encode,
    );
}
