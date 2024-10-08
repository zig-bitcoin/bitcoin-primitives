const DIGITS_OF_PI = [_]u8{
    0x03, 0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73,
    0x44, 0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C,
    0x89, 0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C,
    0x6C, 0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09,
    0x17, 0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5,
    0xAC, 0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E,
    0x96, 0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C,
    0xF7, 0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E,
};

// Subset of test cases from https://github.com/cryptocoinjs/base-x/blob/master/test/fixtures.json
pub const TEST_CASES: []const struct { []const u8, []const u8 } = &.{
    .{ &.{}, "" },
    .{ &.{0x61}, "2g" },
    .{ &.{ 0x62, 0x62, 0x62 }, "a3gV" },
    .{ &.{ 0x63, 0x63, 0x63 }, "aPEr" },
    .{ &.{ 0x57, 0x2e, 0x47, 0x94 }, "3EFU7m" },
    .{ &.{ 0x10, 0xc8, 0x51, 0x1e }, "Rt5zm" },
    .{ &.{ 0x51, 0x6b, 0x6f, 0xcd, 0x0f }, "ABnLTmg" },
    .{
        &.{ 0xbf, 0x4f, 0x89, 0x00, 0x1e, 0x67, 0x02, 0x74, 0xdd },
        "3SEo3LWLoPntC",
    },
    .{
        &.{ 0xec, 0xac, 0x89, 0xca, 0xd9, 0x39, 0x23, 0xc0, 0x23, 0x21 },
        "EJDM8drfXA6uyA",
    },
    .{
        &.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        "1111111111",
    },
    .{
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        "FPBt6CHo3fovdL",
    },
    .{
        &.{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        },
        "NKioeUVktgzXLJ1B3t",
    },
    .{
        &.{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        },
        "YcVfxkQb6JRzqk5kF2tNLv",
    },
    .{
        &.{
            0x73, 0x69, 0x6d, 0x70, 0x6c, 0x79, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20,
            0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
        },
        "2cFupjhnEsSn59qHXstmK2ffpLv2",
    },
    .{
        &.{
            0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60, 0x92, 0x58, 0x86, 0xb6, 0x7d, 0x06,
            0x52, 0x99, 0x92, 0x59, 0x15, 0xae, 0xb1, 0x72, 0xc0, 0x66, 0x47,
        },
        "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
    },
    .{
        &.{
            0x00, 0x3c, 0x17, 0x6e, 0x65, 0x9b, 0xea, 0x0f, 0x29, 0xa3, 0xe9, 0xbf, 0x78, 0x80,
            0xc1, 0x12, 0xb1, 0xb3, 0x1b, 0x4d, 0xc8, 0x26, 0x26, 0x81, 0x87,
        },
        "16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS",
    },
    .{
        &.{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        },
        "11111111111111111111111111111111",
    },
    .{
        &.{
            0x80, 0x11, 0x84, 0xcd, 0x2c, 0xdd, 0x64, 0x0c, 0xa4, 0x2c, 0xfc, 0x3a, 0x09, 0x1c,
            0x51, 0xd5, 0x49, 0xb2, 0xf0, 0x16, 0xd4, 0x54, 0xb2, 0x77, 0x40, 0x19, 0xc2, 0xb2,
            0xd2, 0xe0, 0x85, 0x29, 0xfd, 0x20, 0x6e, 0xc9, 0x7e,
        },
        "5Hx15HFGyep2CfPxsJKe2fXJsCVn5DEiyoeGGF6JZjGbTRnqfiD",
    },
    .{ &DIGITS_OF_PI, "KeThPkHTv5nsa4576Z47NqEtuSfUcKwv7YeueZ8dquGTDeBpimjGEZ1a7k1FCz8m8FEBcoJZjP5Aui6eKfPjdmGooHKtEPRbVotw6mRxNU3WbLtAH41mea9g8AB9Qe1DAFDReBWa67ZEP6ApWGhw9Dfr2vVXkLXEWj6W8HFApw4DKK" },
};

pub const CHECK_TEST_CASE: []const struct { []const u8, []const u8 } = &.{
    .{ &.{}, "3QJmnh" },
    .{ &.{0x31}, "6bdbJ1U" },
    .{ &.{0x39}, "7VsrQCP" },
    .{ &.{ 0x2d, 0x31 }, "PWEu9GGN" },
    .{ &.{ 0x31, 0x31 }, "RVnPfpC2" },
    .{
        &.{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x39, 0x38, 0x37, 0x36, 0x30 },
        "K5zqBMZZTzUbAZQgrt4",
    },
    .{
        &.{
            0x00, 0x9b, 0x41, 0x54, 0xbb, 0xf2, 0x03, 0xe4, 0x13, 0x0c, 0x4b, 0x86, 0x25, 0x93,
            0x18, 0xa4, 0x98, 0x75, 0xdd, 0x04, 0x56,
        },
        "1F9v11cupBVMpz3CrVfCppv9Rw2xEtU1c6",
    },
    .{
        &.{
            0x53, 0x25, 0xb1, 0xe2, 0x3b, 0x5b, 0x24, 0xf3, 0x47, 0xed, 0x19, 0xde, 0x61, 0x23,
            0x8a, 0xf1, 0x4b, 0xc4, 0x71, 0xca, 0xa1, 0xa7, 0x7a, 0xa5, 0x5d, 0xb2, 0xa7, 0xaf,
            0x7d, 0xaa, 0x93, 0xaa,
        },
        "dctKSXBbv2My3TGGUgTFjkxu1A9JM3Sscd5FydY4dkxnfwA7q",
    },
    .{ &DIGITS_OF_PI, "371hJQw3jVfFQtQfQ1NnUFV4Z3i166yKJe3yyPAvJziEfUenJBD8SM6xGFop9cfCDCn4j9HcT9fS73jgGp8XZzYKmSxjxLcxfgETzg4BcDHLgHSynSFDGR5wJ58NkZSv2mVxvqVwG8hqxNFXrWms66ppx45yAjc7dYuBXqCPZ2GatCMmrhuX" },
};

const Encoder = @import("encode.zig").Encoder;
const Decoder = @import("decode.zig").Decoder;
const std = @import("std");

test "encode" {
    for (TEST_CASES) |test_case| {
        var encoder = Encoder{};

        const encoded = try encoder.encodeAlloc(std.testing.allocator, test_case[0]);
        defer std.testing.allocator.free(encoded);

        try std.testing.expectEqualSlices(u8, test_case[1], encoded);
    }
}

test "encode with check" {
    var encoder = Encoder{};

    for (CHECK_TEST_CASE) |test_case| {
        const data = try encoder.encodeCheckAlloc(std.testing.allocator, test_case[0]);
        defer std.testing.allocator.free(data);

        try std.testing.expectEqualSlices(u8, test_case[1], data);
    }
}

test "decode" {
    for (TEST_CASES) |test_case| {
        var decoder = Decoder{};

        const decoded = try decoder.decodeAlloc(std.testing.allocator, test_case[1]);
        defer std.testing.allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, test_case[0], decoded);
    }
}

test "decode with check" {
    var decoder = Decoder{};

    for (CHECK_TEST_CASE) |test_case| {
        const data = try decoder.decodeCheckAlloc(std.testing.allocator, test_case[1]);
        defer std.testing.allocator.free(data);

        try std.testing.expectEqualSlices(u8, test_case[0], data);
    }
}
