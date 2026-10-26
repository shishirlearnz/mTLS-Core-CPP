// -----------------------------------------------------------------------------
// version_test.cpp
//
// Trivial but important: verifies that the compiled mtls_core static library
// actually links into the test binary and returns the expected version string.
// If this fails, our library target is mis-wired (e.g. sources not compiled,
// include path wrong, or the target not linked), which would silently break
// every later layer's tests.
// -----------------------------------------------------------------------------

#include <gtest/gtest.h>

#include "mtls_core/version.hpp"

TEST(VersionTest, ReportsExpectedProjectVersion) {
    // version_string() returns a pointer to a static (zero-terminated) C
    // string; it never returns nullptr. Compare with the value pinned in
    // CMakeLists.txt (project VERSION 0.1.0).
    const char* v = mtls_core::version_string();
    ASSERT_NE(v, nullptr);
    EXPECT_STREQ(v, "0.1.0");
}
