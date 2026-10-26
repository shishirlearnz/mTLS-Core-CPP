// -----------------------------------------------------------------------------
// mtls_core/cipher_suite.hpp
//
// TLS 1.3 cipher-suite code points (IANA / RFC 8446 §B.4) and the "AEAD
// geometry" (key / IV / tag lengths in bytes) of each suite.
//
// These are compile-time constants: no state, no allocations, no crypto yet.
// They exist so later layers (CipherState, RecordLayer) can look up the sizes
// they need without hard-coding magic numbers.
// -----------------------------------------------------------------------------

#pragma once  // Universally supported by MSVC, GCC, and Clang; see note below.

#include <cstddef>   // std::size_t
#include <cstdint>   // std::uint16_t

// NOTE on `#pragma once` vs classic include guards:
//   `#pragma once` is not part of the ISO standard, but every compiler we
//   target (MSVC, GCC, Clang) has supported it for over a decade. It is
//   shorter and immune to copy/paste guard-name collisions. If you ever need
//   100% standard-conformance (e.g. an exotic embedded toolchain), swap it for
//   a classic `#ifndef MTLS_CORE_CIPHER_SUITE_HPP` / `#define` / `#endif` trio.

namespace mtls_core {

// ---------------------------------------------------------------------------
// CipherSuite
// ---------------------------------------------------------------------------
//
// A scoped enum (enum class). Compared to a C++11 `enum`, this:
//   * does not pollute the enclosing namespace with the enumerator names
//     (you must write CipherSuite::TLS_AES_256_GCM_SHA384), and
//   * does not implicitly convert to int, so you cannot accidentally pass a
//     cipher suite where an integer was expected.
//
// The underlying type is std::uint16_t because IANA code points are exactly
// two bytes on the wire. Explicit underlying type also makes static_cast to
// the wire format lossless and well-defined.

enum class CipherSuite : std::uint16_t {
    TLS_AES_128_GCM_SHA256 = 0x1301,        // AES-128-GCM + SHA-256
    TLS_AES_256_GCM_SHA384 = 0x1302,        // AES-256-GCM + SHA-384 (our target)
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,  // ChaCha20-Poly1305 + SHA-256
};

// ---------------------------------------------------------------------------
// AeadParams
// ---------------------------------------------------------------------------
//
// A plain aggregate describing the sizes an AEAD cipher needs for one suite.
// All lengths are in bytes. We keep it a simple struct (no invariants to
// enforce) so it can be used in constexpr contexts and returned by value with
// zero overhead.

struct AeadParams {
    std::size_t key_length;  // length of the traffic key derived from secrets
    std::size_t iv_length;   // length of the fixed IV ("nonce base", RFC 8446 §5.3)
    std::size_t tag_length;  // length of the authentication tag (RFC 8446 §5.2)
};

// ---------------------------------------------------------------------------
// aead_params(CipherSuite)
// ---------------------------------------------------------------------------
//
// Returns the AEAD geometry for a known TLS 1.3 cipher suite, or {0,0,0} for
// an unknown/unsupported suite (a "fail closed" contract).
//
// `constexpr` (C++11 keyword, but here used on a function returning an
// aggregate) means the result is computed at compile time when the argument is
// a compile-time constant — no runtime switch, no branch prediction cost.
//
// Cryptographic rationale for the magic numbers:
//   * key_length: AES-128 => 16, AES-256 => 32, ChaCha20 => 32.
//   * iv_length: 12 for all three. GCM's standard nonce is 96 bits; ChaCha20-
//     Poly1305 in TLS also uses a 96-bit nonce. RFC 8446 §5.3 XORs a 64-bit
//     sequence number into the left-padded fixed IV to form the per-record
//     nonce, so iv_length must be >= 8 (it is 12 here).
//   * tag_length: 16 for ALL TLS 1.3 AEADs. RFC 8446 §5.2: "the authentication
//     tag length is 16 bytes". GCM's default is already 16, and Poly1305 is
//     also 16; TLS fixes it so no negotiation can weaken it.

constexpr AeadParams aead_params(CipherSuite cs) noexcept {
    switch (cs) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
            return {16, 12, 16};
        case CipherSuite::TLS_AES_256_GCM_SHA384:
            return {32, 12, 16};
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            return {32, 12, 16};
        default:
            return {0, 0, 0};  // unknown/unsupported suite
    }
}

}  // namespace mtls_core
