const std = @import("std");
const expectEqualSlices = std.testing.expectEqualSlices;
const alphabet = @import("./alphabet.zig").Alphabet;

/// `Base58Encoder` is a structure for encoding byte slices into Base58 format.
pub const Base58Encoder = struct {
    const Self = @This();

    /// Contains the Base58 alphabet used for encoding.
    ///
    /// This should be initialized with a valid Base58 character set.
    alpha: alphabet = .{},

    /// Encodes a byte slice into Base58 format.
    ///
    /// # Parameters
    ///
    /// * `self`: A pointer to the current instance of `Base58Encoder`.
    /// * `source`: A slice of bytes to encode.
    /// * `dest`: A slice of bytes where the Base58 encoded result will be stored.
    ///
    /// # Description
    ///
    /// This function encodes the provided byte slice (`source`) into Base58 format and
    /// stores the result in the `dest` slice.
    ///
    /// For further information on the Base58 encoding algorithm, see: https://datatracker.ietf.org/doc/html/draft-msporny-base58-03
    pub fn encode(self: *const Self, source: []const u8, dest: []u8) void {
        // Index in the destination slice where the next Base58 character will be written.
        var index: usize = 0;
        // Count of leading zeros in the input data.
        var zero_counter: usize = 0;

        // Count leading zeros in the input source.
        //
        // This loop increments `zero_counter` as long as leading bytes are zero.
        while (zero_counter < source.len and source[zero_counter] == 0) {
            zero_counter += 1;
        }

        // Process the remaining bytes after leading zeros have been handled.
        for (source[zero_counter..]) |val| {
            // Initialize carry with the current byte value.
            var carry: usize = @intCast(val);

            // Encode carry into Base58 digits, modifying the `dest` slice.
            // This loop processes the carry and updates the destination slice accordingly.
            for (dest[0..index]) |*byte| {
                // Add carry to current byte value (multiplied by 256).
                carry += @as(usize, byte.*) << 8;
                // Store the Base58 digit in the destination.
                byte.* = @truncate(carry % @as(usize, 58));
                // Reduce carry for the next iteration.
                carry /= 58;
            }

            // Process any remaining carry and add to the `dest` slice.
            while (carry > 0) {
                // Store the Base58 digit.
                dest[index] = @truncate(carry % 58);
                // Reduce carry for the next iteration.
                carry /= 58;
                // Move to the next position in the destination slice.
                index += 1;
            }
        }

        // Calculate the index where the encoded result ends.
        const dest_index = index + zero_counter;

        // Fill in the leading '1's for the leading zeros in the encoded result.
        // This loop places the correct number of '1' characters at the beginning of `dest`.
        for (dest[index..dest_index]) |*d| {
            d.* = self.alpha.encode[0];
        }

        // Map the Base58 digit values to their corresponding characters using the `alpha` alphabet.
        for (dest[0..index]) |*val| {
            // Convert digit values to Base58 characters.
            val.* = self.alpha.encode[val.*];
        }

        // Reverse the `dest` slice to produce the final encoded result.
        std.mem.reverse(u8, dest[0..dest_index]);
    }
};

test "Base58Encoder: verify encoding" {
    const encoder: Base58Encoder = .{};

    var buf1: [0]u8 = undefined;
    _ = encoder.encode(&[_]u8{}, &buf1);
    try expectEqualSlices(u8, "", &buf1);

    var buf2: [2]u8 = undefined;
    _ = encoder.encode(&[_]u8{0x61}, &buf2);
    try expectEqualSlices(u8, "2g", &buf2);

    var buf3: [4]u8 = undefined;
    _ = encoder.encode(&[_]u8{ 0x62, 0x62, 0x62 }, &buf3);
    try expectEqualSlices(u8, "a3gV", &buf3);

    var buf4: [4]u8 = undefined;
    _ = encoder.encode(&[_]u8{ 0x63, 0x63, 0x63 }, &buf4);
    try expectEqualSlices(u8, "aPEr", &buf4);

    var buf5: [13]u8 = undefined;
    _ = encoder.encode(&[_]u8{ 0xbf, 0x4f, 0x89, 0x00, 0x1e, 0x67, 0x02, 0x74, 0xdd }, &buf5);
    try expectEqualSlices(u8, "3SEo3LWLoPntC", &buf5);

    var buf6: [5]u8 = undefined;
    _ = encoder.encode(&[_]u8{ 0x00, 0x00, 0x01, 0x02, 0x03 }, &buf6);
    try expectEqualSlices(u8, "11Ldp", &buf6);

    var buf7: [1]u8 = undefined;
    _ = encoder.encode(&[_]u8{0x00}, &buf7);
    try expectEqualSlices(u8, "1", &buf7);

    var buf8: [174]u8 = undefined;
    _ = encoder.encode(&[_]u8{
        0x03, 0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73,
        0x44, 0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C,
        0x89, 0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C,
        0x6C, 0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09,
        0x17, 0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5,
        0xAC, 0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E,
        0x96, 0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C,
        0xF7, 0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E,
    }, &buf8);
    try expectEqualSlices(
        u8,
        "KeThPkHTv5nsa4576Z47NqEtuSfUcKwv7YeueZ8dquGTDeBpimjGEZ1a7k1FCz8m8FEBcoJZjP5Aui6eKfPjdmGooHKtEPRbVotw6mRxNU3WbLtAH41mea9g8AB9Qe1DAFDReBWa67ZEP6ApWGhw9Dfr2vVXkLXEWj6W8HFApw4DKK",
        &buf8,
    );
}
