const std = @import("std");
const expectEqualSlices = std.testing.expectEqualSlices;
const expectError = std.testing.expectError;

pub const BITCOIN_ALPHABET: [58]u8 = [58]u8{
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
    'G',
    'H',
    'J',
    'K',
    'L',
    'M',
    'N',
    'P',
    'Q',
    'R',
    'S',
    'T',
    'U',
    'V',
    'W',
    'X',
    'Y',
    'Z',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
};

pub const Alphabet = struct {
    encode: [58]u8,
    decode: [128]u8,

    const Options = struct { alphabet: [58]u8 = BITCOIN_ALPHABET };

    const Self = @This();

    pub const DEFAULT = Self.init(.{}) catch unreachable;

    /// Initialize an Alpabet set with options
    pub fn init(options: Options) !Self {
        var encode = [_]u8{0x00} ** 58;
        var decode = [_]u8{0xFF} ** 128;

        for (options.alphabet, 0..) |b, i| {
            if (b >= 128) {
                return error.NonAsciiChar;
            }
            if (decode[b] != 0xFF) {
                return error.DuplicateCharacter;
            }

            encode[i] = b;
            decode[b] = @intCast(i);
        }

        return .{
            .encode = encode,
            .decode = decode,
        };
    }
};

test "Alphabet: verify Bitcoin alphabet" {
    try expectEqualSlices(
        u8,
        &"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".*,
        &(try Alphabet.init(.{})).encode,
    );
}

test "Alphabet: verify alphabet with non ascii char returns error" {
    try expectError(
        error.NonAsciiChar,
        Alphabet.init(.{ .alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxé".* }),
    );
}

test "Alphabet: verify alphabet with duplicate char returns error" {
    try expectError(
        error.DuplicateCharacter,
        Alphabet.init(.{ .alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyy".* }),
    );
}
