// -----------------------------------------------------------------------------
// mtls_core/version.hpp
//
// Exposes the library's semantic version. This minimal translation unit gives
// the mtls_core static library something real to compile and link, so the test
// target can verify the full build pipeline (compile -> archive -> link ->
// execute) before any cryptographic code exists.
// -----------------------------------------------------------------------------

#pragma once

namespace mtls_core {

// Returns a pointer to a static, zero-terminated version string (e.g. "0.1.0").
// The pointer is never null and remains valid for the lifetime of the program.
// Returning a `const char*` (a C-style string) rather than std::string keeps
// this header free of any allocation and trivially linkable from C if needed.
const char* version_string() noexcept;

}  // namespace mtls_core
