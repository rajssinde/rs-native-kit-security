#pragma once

// Path probe for the Swift detectors that bypasses hooks. Jailbreak-hiding
// tweaks (Shadow, A-Bypass, ...) hook FileManager *and* libc's stat/access/
// open to hide jailbreak files from apps. On arm64 this issues the access(2)
// system call directly with `svc #0x80`, which neither kind of hook sees;
// elsewhere (x86_64 Simulator) it falls back to libc. Comparing its answer
// with FileManager's is itself a hook-detection signal.

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 1 if `path` exists, 0 if not (or on error).
static inline int rs_raw_path_exists(const char *path) {
#if defined(__arm64__) || defined(__aarch64__)
  register long x16 __asm__("x16") = 33; // SYS_access
  register long x0 __asm__("x0") = (long)path;
  register long x1 __asm__("x1") = F_OK;
  __asm__ volatile(
      "svc #0x80\n"
      "b.cc 1f\n"          // carry clear: success, x0 = result
      "mov x0, #-1\n"      // carry set: failure, x0 = errno -> normalise to -1
      "1:\n"
      : "+r"(x0)
      : "r"(x16), "r"(x1)
      : "memory", "cc");
  return x0 == 0 ? 1 : 0;
#else
  return access(path, F_OK) == 0 ? 1 : 0;
#endif
}

#ifdef __cplusplus
}
#endif
