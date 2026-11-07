#pragma once

// Raw-syscall probes for the Swift detectors that bypass hooks. Jailbreak-hiding
// tweaks (Shadow, A-Bypass, ...) hook FileManager *and* libc's stat/access/
// open to hide jailbreak files from apps. On arm64 these issue the system
// calls directly with `svc #0x80`, which neither kind of hook sees;
// elsewhere (x86_64 Simulator) they fall back to libc or report "unknown".
// Comparing the raw path probe with FileManager is itself a hook-detection signal.

#include <stdint.h>
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

/// Code-signing status flags of this process (csops CS_OPS_STATUS), or -1 on
/// error / where unavailable. The kernel sets CS_DEBUGGED (0x10000000) once a
/// debugger has attached, and it stays set after the debugger detaches.
static inline int64_t rs_raw_cs_status(void) {
#if defined(__arm64__) || defined(__aarch64__)
  uint32_t flags = 0;
  register long x16 __asm__("x16") = 169; // SYS_csops
  register long x0 __asm__("x0") = (long)getpid();
  register long x1 __asm__("x1") = 0;     // CS_OPS_STATUS
  register long x2 __asm__("x2") = (long)&flags;
  register long x3 __asm__("x3") = sizeof(flags);
  __asm__ volatile(
      "svc #0x80\n"
      "b.cc 1f\n"
      "mov x0, #-1\n"
      "1:\n"
      : "+r"(x0)
      : "r"(x16), "r"(x1), "r"(x2), "r"(x3)
      : "memory", "cc");
  return x0 == 0 ? (int64_t)flags : -1;
#else
  return -1;
#endif
}

#ifdef __cplusplus
}
#endif
