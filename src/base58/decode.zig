const std = @import("std");
const expectEqualSlices = std.testing.expectEqualSlices;
const Alphabet = @import("./alphabet.zig").Alphabet;

/// `Base58Encoder` is a structure for encoding byte slices into Base58 format.
pub const Decoder = struct {
    const Self = @This();

    /// Contains the Base58 alphabet used for encoding.
    ///
    /// This should be initialized with a valid Base58 character set.
    alpha: Alphabet = Alphabet.init(.{}) catch unreachable,

    /// Pass a `allocator` & `encoded` bytes buffer. `decodeAlloc` will allocate a buffer
    /// to write into. It may also realloc as needed. Returned value is proper size.
    pub fn decodeAlloc(self: *const Self, allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        var dest = try allocator.alloc(u8, encoded.len);

        const size = try self.decode(encoded, dest);
        if (dest.len != size) {
            dest = try allocator.realloc(dest, size);
        }

        return dest;
    }

    /// Pass a `encoded` and a `dest` to write decoded value into. `decode` returns a
    /// `usize` indicating how many bytes were written. Sizing/resizing, `dest` buffer is up to the caller.
    ///
    /// For further information on the Base58 decoding algorithm, see: https://datatracker.ietf.org/doc/html/draft-msporny-base58-03
    pub fn decode(self: *const Self, encoded: []const u8, dest: []u8) !usize {
        var index: usize = 0;
        const zero = self.alpha.encode[0];

        for (encoded) |c| {
            if (c > 127) {
                return error.NonAsciiCharacter;
            }

            var val: usize = self.alpha.decode[c];
            if (val == 0xFF) {
                return error.InvalidCharacter;
            }

            for (dest[0..index]) |*byte| {
                val += @as(usize, @intCast(byte.*)) * 58;
                byte.* = @intCast(val & 0xFF);
                val >>= 8;
            }

            while (val > 0) {
                if (index >= dest.len) {
                    return error.BufferTooSmall;
                }

                dest[index] = @as(u8, @intCast(val)) & 0xFF;
                index += 1;
                val >>= 8;
            }
        }

        for (encoded) |c| {
            if (c != zero) break;

            dest[index] = 0;
            index += 1;
        }

        std.mem.reverse(u8, dest[0..index]);

        return index;
    }

    /// Decode a base58-encoded string (str)
    /// that includes a checksum into a byte
    /// is successful return decoded otherwise error
    pub fn decodeCheckAlloc(decoder: *const Decoder, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const decoded = try decoder.decodeAlloc(allocator, data);
        errdefer allocator.free(decoded);

        if (decoded.len < 4) return error.TooShortError;

        const check_start = decoded.len - 4;

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        hasher.update(decoded[0..check_start]);
        const fr = hasher.finalResult();

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&fr);

        const expected = std.mem.readInt(u32, hasher.finalResult()[0..4], .little);
        const actual = std.mem.readInt(u32, decoded[check_start..][0..4], .little);

        if (expected != actual) return error.IncorrectChecksum;

        return try allocator.realloc(decoded, check_start);
    }
};
