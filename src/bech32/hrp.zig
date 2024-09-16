const std = @import("std");
const expect = std.testing.expect;
const expectEqualSlices = std.testing.expectEqualSlices;
const expectError = std.testing.expectError;
const expectEqualStrings = std.testing.expectEqualStrings;

/// The human readable part of a bech32 address is limited to 83 US-ASCII characters.
const MAX_HRP_LEN: usize = 83;

/// The minimum ASCII value for a valid character in the human readable part.
const MIN_ASCII: u8 = 33;

/// The maximum ASCII value for a valid character in the human readable part.
const MAX_ASCII: u8 = 126;

/// The human-readable part (HRP) for the Bitcoin mainnet.
///
/// This corresponds to `bc` prefix.
///
/// Example:
///  - Mainnet P2WPKH: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
const BC: Hrp = .{
    .buf = [_]u8{
        98, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0, 0, 0,
    },
    .size = 2,
};

/// The human-readable part (HRP) for Bitcoin testnet networks (testnet and signet).
///
/// This corresponds to `tb` prefix.
///
/// Example:
/// - Testnet P2WPKH: tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
const TB: Hrp = .{
    .buf = [_]u8{
        116, 98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,   0,  0, 0, 0,
    },
    .size = 2,
};

/// The human-readable part (HRP) for the Bitcoin regtest network.
///
/// This corresponds to `bcrt` prefix.
const BCRT: Hrp = .{
    .buf = [_]u8{
        98, 99, 114, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0,  0,   0,   0,
    },
    .size = 4,
};

/// Various errors that can occur during HRP processing.
///
/// These errors help in validating and debugging issues with bech32 address formatting.
const HrpError = error{
    /// This error occurs when the provided human-readable part (HRP) is empty.
    ///
    /// A valid HRP must contain at least one character to comply with the
    /// specification, and this error signals the absence of such a character.
    EmptyHrp,

    /// This error is returned when the HRP exceeds the maximum allowed length.
    ///
    /// According to the specification, the HRP must not exceed 83 characters.
    /// This error occurs if the HRP length is greater than the allowed limit.
    TooLongHrp,

    /// This error occurs when a non-ASCII character is found in the HRP.
    ///
    /// The HRP is restricted to US-ASCII characters (values between 33 and 126).
    /// This error indicates that a character outside of this range was encountered.
    NonAsciiChar,

    /// This error is returned when the HRP contains a character that falls
    /// outside the valid ASCII range for a bech32-encoded string.
    ///
    /// The HRP should only contain characters within the range of 33 to 126.
    /// If a character falls outside of this range, this error is triggered.
    InvalidAsciiByte,

    /// This error occurs when the HRP contains both uppercase and lowercase letters.
    ///
    /// To ensure consistency and compatibility, the HRP must either be fully
    /// lowercase or fully uppercase. Mixing of cases is not allowed, and this
    /// error indicates a violation of that rule.
    MixedCaseHrp,
};

/// Represents the human-readable part (HRP) of a Bech32 encoded string.
///
/// The HRP is the prefix of a Bech32 string that is used to convey contextual information about the
/// encoded data (such as the blockchain network or address type).
///
/// The Bech32 specification, defined in [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki),
/// restricts the HRP to 1-83 characters from the US-ASCII set, with the characters required to be in the range
/// of ASCII values 33-126.
/// Furthermore, HRP must not be mixed-case (i.e., it cannot contain both uppercase and lowercase letters).
pub const Hrp = struct {
    const Self = @This();

    /// ASCII buffer for the human readable part.
    ///
    /// This buffer stores the validated HRP string characters and is initialized to zeros.
    /// The size of the buffer is fixed at `MAX_HRP_LEN` (83 bytes) to match the Bech32 specification.
    ///
    /// # Guarantee:
    /// The buffer ensures that no mixed-case characters are stored in the HRP (all characters will either be lowercase
    /// or uppercase, but not both).
    buf: [MAX_HRP_LEN]u8 = [_]u8{0} ** MAX_HRP_LEN,
    /// The number of characters currently stored in the HRP.
    ///
    /// This value tracks how many bytes from the buffer are actively used for the HRP. It will always be
    /// less than or equal to `MAX_HRP_LEN`.
    size: usize = 0,

    /// Parses and validates a human-readable part (HRP) according to the Bech32 specification.
    ///
    /// This function checks that the provided `hrp` string is valid according to the Bech32 rules as defined in
    /// BIP-173. The HRP must:
    ///
    /// - Be between 1 and 83 characters in length.
    /// - Contain only valid US-ASCII characters within the range [33-126].
    /// - Not be mixed-case, meaning it must either be all lowercase or all uppercase, but not both.
    ///
    /// # Parameters:
    /// - `hrp`: A byte slice representing the HRP string to validate.
    ///
    /// # Returns:
    /// - Returns an `Hrp` struct if the HRP is valid.
    /// - Returns an error if the HRP is empty, too long, contains invalid characters, or is mixed-case.
    pub fn parse(hrp: []const u8) HrpError!Self {
        // Check if the provided HRP is empty, as an HRP must contain at least one character.
        if (hrp.len == 0)
            return HrpError.EmptyHrp;

        // Check if the HRP exceeds the maximum allowed length of 83 characters, returning an error if it does.
        if (hrp.len > MAX_HRP_LEN)
            return HrpError.TooLongHrp;

        // Create a new instance of the `Hrp` struct, initializing the buffer with zeros and size with 0.
        var new = Self{};

        // Flags to detect if there are any lowercase or uppercase letters in the HRP.
        var has_lower = false;
        var has_upper = false;

        // Loop through each character of the HRP by its index `i` and character `c`.
        for (hrp, 0..) |c, i| {

            // Check if the current character is a valid ASCII character (0-127).
            if (!std.ascii.isAscii(c))
                return HrpError.NonAsciiChar;

            // Ensure that the character is within the valid range of ASCII values for Bech32 (33-126).
            // Characters outside this range are invalid.
            if (c < MIN_ASCII or c > MAX_ASCII)
                return HrpError.InvalidAsciiByte;

            // If the character is lowercase, ensure that no uppercase characters have been encountered so far.
            // If an uppercase character was already found, return a `MixedCaseHrp` error.
            if (std.ascii.isLower(c)) {
                if (has_upper)
                    return HrpError.MixedCaseHrp;

                // Mark that a lowercase letter has been found.
                has_lower = true;
            } else if (std.ascii.isUpper(c)) {
                // If the character is uppercase, ensure that no lowercase characters have been encountered.
                // If a lowercase character was already found, return a `MixedCaseHrp` error.
                if (has_lower)
                    return HrpError.MixedCaseHrp;

                // Mark that an uppercase letter has been found.
                has_upper = true;
            }

            // Store the valid character into the buffer at the current index.
            new.buf[i] = c;
            // Increment the size of the HRP by 1 to account for the newly added character.
            new.size += 1;
        }

        // Return the constructed and validated `Hrp` instance.
        return new;
    }

    /// Converts the human-readable part (HRP) to a lowercase representation.
    pub fn toLowerCase(self: *const Self, output: []u8) []const u8 {
        std.debug.assert(output.len >= self.size);

        // Loop through each character of the HRP and convert it to lowercase.
        for (self.buf[0..self.size], 0..) |b, i| {
            output[i] = std.ascii.toLower(b);
        }

        return output[0..self.size];
    }

    /// Converts the human-readable part (HRP) to bytes.
    pub fn asBytes(self: *const Self) []const u8 {
        return self.buf[0..self.size];
    }

    /// Checks whether two HRPs are equal.
    pub fn eql(self: *const Self, rhs: *const Self) bool {
        // If the HRPs have different sizes, they are not equal.
        if (self.size != rhs.size) return false;

        // Create buffers to store the lowercase versions of the HRPs.
        var buf_lhs: [MAX_HRP_LEN]u8 = undefined;
        var buf_rhs: [MAX_HRP_LEN]u8 = undefined;

        // Convert both HRPs to lowercase.
        const l = self.toLowerCase(&buf_lhs);
        const r = rhs.toLowerCase(&buf_rhs);

        // Compare each byte of the lowercase HRPs for equality.
        for (l, r) |a, b|
            if (a != b) return false;

        return true;
    }

    /// Checks whether a given Segwit address is valid on either the mainnet or testnet.
    ///
    /// A Segwit address must follow the Bech32 encoding format, with the human-readable
    /// part "bc" for mainnet or "tb" for testnet. This function combines the logic of
    /// validating an address on both networks.
    ///
    /// # Returns
    /// - `true` if the Segwit address is valid on either the mainnet or testnet.
    /// - `false` otherwise.
    ///
    /// # Segwit Address Requirements:
    /// - The human-readable part must be "bc" (mainnet) or "tb" (testnet).
    /// - The witness program must follow the rules outlined in BIP141.
    pub fn isValidSegwit(self: *const Self) bool {
        return self.isValidOnMainnet() or self.isValidOnTestnet();
    }

    /// Checks whether a given Segwit address is valid on the Bitcoin mainnet.
    ///
    /// Segwit addresses on the mainnet use the human-readable part "bc". This function
    /// verifies that the provided address corresponds to the mainnet format.
    ///
    /// # Returns
    /// - `true` if the Segwit address is valid on the mainnet (with the "bc" prefix).
    /// - `false` otherwise.
    pub fn isValidOnMainnet(self: *const Self) bool {
        return self.eql(&BC);
    }

    /// Checks whether a given Segwit address is valid on the Bitcoin testnet.
    ///
    /// Segwit addresses on the testnet use the human-readable part "tb". This function
    /// verifies that the provided address corresponds to the testnet format.
    ///
    /// # Returns
    /// - `true` if the Segwit address is valid on the testnet (with the "tb" prefix).
    /// - `false` otherwise.
    pub fn isValidOnTestnet(self: *const Self) bool {
        return self.eql(&TB);
    }

    /// Checks whether a given Segwit address is valid on the Bitcoin signet.
    ///
    /// Segwit addresses on signet also use the human-readable part "tb", similar to
    /// testnet addresses. This function verifies that the provided address corresponds
    /// to the signet format.
    ///
    /// # Returns
    /// - `true` if the Segwit address is valid on signet (with the "tb" prefix).
    /// - `false` otherwise.
    pub fn isValidOnSignet(self: *const Self) bool {
        return self.eql(&TB);
    }

    /// Checks whether a given Segwit address is valid on the Bitcoin regtest network.
    ///
    /// Segwit addresses on the regtest network use the human-readable part "bcrt".
    /// This function verifies that the provided address corresponds to the regtest
    /// format.
    ///
    /// # Returns
    /// - `true` if the Segwit address is valid on regtest (with the "bcrt" prefix).
    /// - `false` otherwise.
    pub fn isValidOnRegtest(self: *const Self) bool {
        return self.eql(&BCRT);
    }
};

test "Hrp: check parse is ok" {
    // Some valid human readable parts.
    //
    // Taken from https://github.com/rust-bitcoin/rust-bech32/blob/master/src/primitives/hrp.rs
    const cases = [_][]const u8{
        "a",
        "A",
        "abcdefg",
        "ABCDEFG",
        "abc123def",
        "ABC123DEF",
        "!\"#$%&'()*+,-./",
        "1234567890",
    };

    // Go through all the test cases.
    for (cases) |c| {
        // Check that the human readable part is parsed correctly.
        const hrp = try Hrp.parse(c);
        // Check that the human readable part is correctly stored in the buffer.
        try expectEqualSlices(u8, c, hrp.buf[0..hrp.size]);
        // Check that the remaining buffer is zeroed.
        for (hrp.buf[hrp.size..]) |b| try expect(b == 0);
        // Check that the size is correct.
        try expect(hrp.size == c.len);
    }
}

test "Hrp: mixed case Hrp should fail parsing" {
    // A human readable part that contains both uppercase and lowercase characters.
    const case = "has-capitals-aAbB";
    // Attempt to parse the mixed-case HRP, expecting a `MixedCaseHrp` error.
    try expectError(HrpError.MixedCaseHrp, Hrp.parse(case));
}

test "Hrp: empty Hrp should fail parsing" {
    // An empty human readable part.
    const case = "";
    // Attempt to parse the empty HRP, expecting an `EmptyHrp` error.
    try expectError(HrpError.EmptyHrp, Hrp.parse(case));
}

test "Hrp: Hrp with non ASCII character should fail parsing" {
    // A human readable part that contains invalid ASCII characters.
    const case = "has-value-out-of-range-∈∈∈∈∈∈∈∈";
    // Attempt to parse the HRP with invalid characters, expecting an `InvalidAsciiByte` error.
    try expectError(HrpError.NonAsciiChar, Hrp.parse(case));
}

test "Hrp: Hrp with too many characters should fail parsing" {
    // A human readable part that exceeds the maximum allowed length.
    const case = "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong";
    // Attempt to parse the HRP that is too long, expecting a `TooLongHrp` error.
    try expectError(HrpError.TooLongHrp, Hrp.parse(case));
}

test "Hrp: Hrp with invalid ASCII byte should fail parsing" {
    // A human readable part that contains invalid ASCII characters.
    const case = "has spaces in it";
    // Attempt to parse the HRP with invalid characters, expecting an `InvalidAsciiByte` error.
    try expectError(HrpError.InvalidAsciiByte, Hrp.parse(case));
}

test "Hrp: Hrp to lower case" {
    // Some valid human readable parts.
    const cases = [_][]const u8{
        "a",
        "A",
        "abcdefg",
        "ABCDEFG",
        "abc123def",
        "ABC123DEF",
        "!\"#$%&'()*+,-./",
        "1234567890",
    };

    // The expected results for the human readable parts in lowercase.
    const expected_results = [_][]const u8{
        "a",
        "a",
        "abcdefg",
        "abcdefg",
        "abc123def",
        "abc123def",
        "!\"#$%&'()*+,-./",
        "1234567890",
    };

    // Go through all the test cases.
    for (cases, expected_results) |case, expected| {
        // Parse the human readable part.
        const hrp = try Hrp.parse(case);
        var buf: [MAX_HRP_LEN]u8 = undefined;

        // Convert the human readable part to lowercase.
        try expectEqualStrings(expected, hrp.toLowerCase(&buf));
    }
}

test "Hrp: as bytes should return the proper bytes" {
    // Some valid human readable parts.
    const cases = [_][]const u8{
        "a",
        "A",
        "abcdefg",
        "ABCDEFG",
        "abc123def",
        "ABC123DEF",
        "!\"#$%&'()*+,-./",
        "1234567890",
    };

    // Go through all the test cases.
    for (cases) |case| {
        // Parse the human readable part.
        const hrp = try Hrp.parse(case);
        // Convert the human readable part to lowercase.
        try expectEqualSlices(u8, case, hrp.asBytes());
    }
}

test "Hrp: ensure eql function works properly" {
    // Parse two human readable parts which are equal.
    const lhs1 = try Hrp.parse("!\"#$%&'()*+,-./");
    const rhs1 = try Hrp.parse("!\"#$%&'()*+,-./");
    // Assert that the two human readable parts are equal.
    try expect(lhs1.eql(&rhs1));

    // Generate another human readable part which is different.
    const rhs2 = try Hrp.parse("!\"#$%&'()*+,-.a");
    // Assert that the two human readable parts are not equal.
    try expect(!lhs1.eql(&rhs2));

    // Generate another human readable part with a different size.
    const rhs3 = try Hrp.parse("!\"#$%&'()*+,-.");
    // Assert that the two human readable parts are not equal (different size).
    try expect(!lhs1.eql(&rhs3));

    // Parse two human readable parts which are equal, but with different case.
    const lhs_case_insensitive = try Hrp.parse("abcdefg");
    const rhs_case_insensitive = try Hrp.parse("ABCDEFG");
    // Assert that the two human readable parts are equal.
    try expect(lhs_case_insensitive.eql(&rhs_case_insensitive));
}

test "Hrp: ensure constants are properly setup" {
    try expect(BC.eql(&(try Hrp.parse("bc"))));
    try expect(TB.eql(&(try Hrp.parse("tb"))));
    try expect(BCRT.eql(&(try Hrp.parse("bcrt"))));
}
