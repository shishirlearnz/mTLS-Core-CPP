// -----------------------------------------------------------------------------
// cipher_suite_test.cpp
//
// Unit tests for the TLS 1.3 cipher-suite code points and their AEAD geometry
// (key / IV / tag lengths). These are pure compile-time facts, so they are the
// ideal first target: they prove the CMake + GoogleTest pipeline compiles,
// links, and executes, before any cryptographic code exists.
//
// What we are verifying and why it matters (cryptographic rationale):
//   * The IANA code point for TLS_AES_256_GCM_SHA384 is 0x1302. If we got this
//     wrong, the ClientHello/ServerHello wire bytes would advertise a different
//     (or unknown) suite and every handshake would fail. These are the same
//     bytes that appear on the wire, so they must match IANA exactly.
//   * AES-256-GCM uses a 32-byte key, a 12-byte fixed IV/nonce, and — per
//     RFC 8446 §5.2 — a 16-byte authentication tag. The tag length is NOT
//     negotiable in TLS 1.3; it is fixed at 16 bytes for all AEADs.
// -----------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "mtls_core/cipher_suite.hpp"

using mtls_core::AeadParams;
using mtls_core::CipherSuite;
using mtls_core::aead_params;

// --- Positive: code points must match IANA --------------------------------
//
// RFC 8446 §B.4 and the IANA "TLS Cipher Suites" registry assign these
// 2-byte code points. We compare against std::uint16_t to avoid any signed/
// unsigned comparison ambiguity (a source of -Wsign-conversion warnings).

TEST(CipherSuiteTest, Aes128GcmSha256CodePointMatchesIana) {
    // 0x1301 == TLS_AES_128_GCM_SHA256
    EXPECT_EQ(static_cast<std::uint16_t>(CipherSuite::TLS_AES_128_GCM_SHA256),
              std::uint16_t{0x1301});
}

TEST(CipherSuiteTest, Aes256GcmSha384CodePointMatchesIana) {
    // 0x1302 == TLS_AES_256_GCM_SHA384  (the suite this project targets)
    EXPECT_EQ(static_cast<std::uint16_t>(CipherSuite::TLS_AES_256_GCM_SHA384),
              std::uint16_t{0x1302});
}

TEST(CipherSuiteTest, ChaCha20Poly1305CodePointMatchesIana) {
    // 0x1303 == TLS_CHACHA20_POLY1305_SHA256
    EXPECT_EQ(static_cast<std::uint16_t>(CipherSuite::TLS_CHACHA20_POLY1305_SHA256),
              std::uint16_t{0x1303});
}

// --- Positive: AEAD geometry ----------------------------------------------
//
// aead_params() is a constexpr function: it is evaluated at compile time, so
// there is no runtime cost and no possibility of the switch failing at runtime.

TEST(CipherSuiteTest, Aes256GcmGeometryIsCorrect) {
    constexpr AeadParams p = aead_params(CipherSuite::TLS_AES_256_GCM_SHA384);
    EXPECT_EQ(p.key_length, std::size_t{32});  // AES-256 => 256-bit key
    EXPECT_EQ(p.iv_length, std::size_t{12});   // GCM default nonce length
    EXPECT_EQ(p.tag_length, std::size_t{16});  // RFC 8446 §5.2 mandates 16
}

TEST(CipherSuiteTest, Aes128GcmGeometryIsCorrect) {
    constexpr AeadParams p = aead_params(CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_EQ(p.key_length, std::size_t{16});  // AES-128 => 128-bit key
    EXPECT_EQ(p.iv_length, std::size_t{12});
    EXPECT_EQ(p.tag_length, std::size_t{16});
}

TEST(CipherSuiteTest, ChaCha20Poly1305GeometryIsCorrect) {
    constexpr AeadParams p = aead_params(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    EXPECT_EQ(p.key_length, std::size_t{32});  // ChaCha20 => 256-bit key
    EXPECT_EQ(p.iv_length, std::size_t{12});   // Poly1305 nonce is 12 bytes
    EXPECT_EQ(p.tag_length, std::size_t{16});  // still 16 in TLS 1.3
}

// --- Negative: unknown suite yields zeroed geometry -----------------------
//
// aead_params() returns {0,0,0} for anything outside the known TLS 1.3 set.
// This is a defensive "fail closed" contract: callers can detect an
// unsupported suite by checking key_length == 0 rather than reading garbage.

TEST(CipherSuiteTest, UnknownSuiteReturnsZeroedGeometry) {
    constexpr AeadParams p = aead_params(static_cast<CipherSuite>(0xFFFF));
    EXPECT_EQ(p.key_length, std::size_t{0});
    EXPECT_EQ(p.iv_length, std::size_t{0});
    EXPECT_EQ(p.tag_length, std::size_t{0});
}
