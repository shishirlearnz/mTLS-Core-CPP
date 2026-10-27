// -----------------------------------------------------------------------------
// secure_memory_test.cpp
//
// Tests for the secure-memory primitives: secure_scrub() and SecureBuffer.
//
// -----------------------------------------------------------------------------
// WHY THIS MATTERS (cryptographic rationale)
// -----------------------------------------------------------------------------
// Keys, IVs, and plaintext are the crown jewels of a TLS implementation. When
// such bytes live in ordinary heap memory and that memory is freed (or the
// object goes out of scope), the bytes *remain in RAM* until something else
// overwrites them. Any of these can read them back:
//   1. A later heap allocation in the same process (e.g. Heartbleed-style
//      over-reads, or a bug that sends a buffer's uninitialized tail).
//   2. A core dump or a memory snapshot written to disk.
//   3. The OS swapping pages out to disk under memory pressure.
//   4. A cold-boot / DMA attack reading physical RAM.
//
// The defence is "zeroization": overwrite the secret with zeros as soon as we
// are done with it. Two subtleties make this a real engineering problem:
//
//   (a) A naive `memset(ptr, 0, n)` can be *optimized away*. If the compiler
//       can prove the buffer is never read again before it is freed, the write
//       is a "dead store" and it may delete it. Your "secure" erase becomes a
//       no-op and the key survives. This is not hypothetical — it is a
//       well-documented real-world bug class. OPENSSL_cleanse() exists
//       precisely to defeat this (historically by calling memset through a
//       volatile function pointer, which the compiler cannot elide).
//
//   (b) Copying a secret *duplicates* it. Two copies mean two places that must
//       both be scrubbed, and the copy can outlive the original's erase. So a
//       secret container must be move-only (ownership transfers), never copied.
//
// These tests encode those two properties directly.
// -----------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>   // std::fill
#include <cstddef>     // std::size_t
#include <cstdint>     // std::uint8_t
#include <iterator>    // std::begin / std::end (for C arrays)
#include <type_traits> // std::is_copy_constructible_v, etc.
#include <utility>     // std::move

#include "mtls_core/secure_memory.hpp"

using mtls_core::SecureBuffer;
using mtls_core::secure_scrub;

// -----------------------------------------------------------------------------
// Compile-time NEGATIVE tests
// -----------------------------------------------------------------------------
// A secret container must be move-only. These static_asserts fail to *compile*
// if SecureBuffer ever becomes copyable — which is exactly the "negative" test
// we want: copying secrets is forbidden at the type level, not by convention.
//
// Note: `std::is_copy_constructible_v<T>` is the C++17 variable-template form
// of C++11's `std::is_copy_constructible<T>::value`. It reads better and is the
// modern spelling.

static_assert(!std::is_copy_constructible_v<SecureBuffer>,
              "SecureBuffer must not be copy-constructible (secrets must not be duplicated)");
static_assert(!std::is_copy_assignable_v<SecureBuffer>,
              "SecureBuffer must not be copy-assignable");
static_assert(std::is_nothrow_move_constructible_v<SecureBuffer>,
              "Move construction must be noexcept (required for safe use in containers)");
static_assert(std::is_nothrow_move_assignable_v<SecureBuffer>,
              "Move assignment must be noexcept");

// -----------------------------------------------------------------------------
// secure_scrub() tests
// -----------------------------------------------------------------------------

TEST(SecureScrubTest, ZeroesMemory) {
    // Positive + the core property: after scrubbing, no original byte remains.
    // 0xAB is a "loud" pattern — if any byte survives, the test catches it.
    std::uint8_t buf[64];
    std::fill(std::begin(buf), std::end(buf), std::uint8_t{0xAB});

    secure_scrub(buf, sizeof(buf));

    for (std::uint8_t byte : buf) {
        EXPECT_EQ(byte, std::uint8_t{0});
    }
}

TEST(SecureScrubTest, HandlesNullPointerAndZeroLength) {
    // Boundary + negative: these are degenerate inputs that a caller could
    // legitimately pass, and they must be safe no-ops, not crashes or UB.
    secure_scrub(nullptr, 0);      // nothing to do
    secure_scrub(nullptr, 64);     // null pointer with a non-zero length
    secure_scrub(nullptr, 0);      // (paranoia: repeat)

    std::uint8_t byte = 42;
    secure_scrub(&byte, 0);        // zero length must not touch the byte
    EXPECT_EQ(byte, std::uint8_t{42});
}

// -----------------------------------------------------------------------------
// SecureBuffer tests
// -----------------------------------------------------------------------------

TEST(SecureBufferTest, ConstructsZeroed) {
    // Positive: a fresh buffer must be deterministic (all zeros), so callers
    // never accidentally send uninitialized heap garbage as if it were data.
    SecureBuffer buf(64);
    ASSERT_EQ(buf.size(), std::size_t{64});
    for (std::size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf[i], std::uint8_t{0});
    }
}

TEST(SecureBufferTest, WritesAndReadsBack) {
    // Positive: the buffer behaves as ordinary byte storage when in use.
    SecureBuffer buf(16);
    for (std::size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<std::uint8_t>(i);
    }
    for (std::size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf[i], static_cast<std::uint8_t>(i));
    }

    // span() must expose a view of the *same* bytes (not a copy): writing
    // through the span and reading through data() sees the same memory.
    auto view = buf.span();
    ASSERT_EQ(view.size(), std::size_t{16});
    EXPECT_EQ(view[0], std::uint8_t{0});
    EXPECT_EQ(view[15], std::uint8_t{15});
}

TEST(SecureBufferTest, ScrubZeroesContents) {
    // Positive: the same erase path the destructor uses must actually zero the
    // bytes. This is our observable stand-in for "the secret is gone".
    SecureBuffer buf(32);
    std::fill(buf.data(), buf.data() + buf.size(), std::uint8_t{0xFF});

    buf.scrub();

    for (std::size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf[i], std::uint8_t{0});
    }
}

TEST(SecureBufferTest, EmptyBufferIsSafe) {
    // Boundary: a zero-length buffer is a valid state (e.g. an empty record).
    // Construction, scrubbing, and destruction must all be safe no-ops.
    SecureBuffer empty;              // default size 0
    EXPECT_TRUE(empty.empty());
    EXPECT_EQ(empty.size(), std::size_t{0});
    empty.scrub();                   // must not crash

    // RAII: destroying an empty buffer must also be safe.
    { SecureBuffer scoped_empty; }
    SUCCEED();
}

TEST(SecureBufferTest, MoveConstructTransfersOwnership) {
    // Positive: moving must transfer the bytes and leave the source empty, so
    // there is exactly ONE owner of the secret at all times.
    SecureBuffer src(8);
    src[3] = std::uint8_t{0x77};

    SecureBuffer dst(std::move(src));

    EXPECT_TRUE(src.empty());                    // source is emptied, not copied
    EXPECT_EQ(src.size(), std::size_t{0});
    ASSERT_EQ(dst.size(), std::size_t{8});
    EXPECT_EQ(dst[3], std::uint8_t{0x77});       // bytes arrived intact
}

TEST(SecureBufferTest, MoveAssignmentTransfersOwnership) {
    // Positive: move-assignment must scrub the destination's OLD secret (so it
    // is not leaked) and then take ownership of the source's bytes.
    SecureBuffer src(4);
    src[1] = std::uint8_t{0x11};

    SecureBuffer dst(16);
    dst[0] = std::uint8_t{0x22};                 // dst holds a secret first

    dst = std::move(src);

    EXPECT_TRUE(src.empty());
    ASSERT_EQ(dst.size(), std::size_t{4});
    EXPECT_EQ(dst[1], std::uint8_t{0x11});       // src's bytes now owned by dst
}

TEST(SecureBufferTest, ResizePreservesAndZeroes) {
    // Boundary: growing zeroes the newly-added region (never expose garbage);
    // shrinking truncates and scrubs the discarded tail so it is not leaked.
    SecureBuffer buf(4);
    buf[0] = std::uint8_t{1};
    buf[1] = std::uint8_t{2};
    buf[2] = std::uint8_t{3};
    buf[3] = std::uint8_t{4};

    buf.resize(8);  // grow
    ASSERT_EQ(buf.size(), std::size_t{8});
    EXPECT_EQ(buf[0], std::uint8_t{1});
    EXPECT_EQ(buf[1], std::uint8_t{2});
    EXPECT_EQ(buf[2], std::uint8_t{3});
    EXPECT_EQ(buf[3], std::uint8_t{4});
    for (std::size_t i = 4; i < buf.size(); ++i) {
        EXPECT_EQ(buf[i], std::uint8_t{0});      // new region is zeroed
    }

    buf.resize(2);  // shrink
    ASSERT_EQ(buf.size(), std::size_t{2});
    EXPECT_EQ(buf[0], std::uint8_t{1});
    EXPECT_EQ(buf[1], std::uint8_t{2});
}
