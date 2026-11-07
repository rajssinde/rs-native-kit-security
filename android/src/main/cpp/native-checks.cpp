// Low-level file probes for the Kotlin detectors (util/NativeChecks.kt).
//
// Root-hiding and instrumentation tools commonly hook the Java file APIs
// (File.exists, FileInputStream) or libc's access/open/stat to hide su,
// Magisk and Frida from apps. On arm64 these probes issue the system call
// directly with an `svc` instruction, so neither kind of hook sees them; on
// other ABIs they fall back to libc's syscall(). Comparing their answers with
// the Java APIs' answers is itself a hook-detection signal.

#include <jni.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cerrno>
#include <string>

namespace {

constexpr size_t kMaxFileBytes = 8 * 1024 * 1024;

#if defined(__aarch64__)
long rawSyscall(long number, long a0, long a1, long a2, long a3) {
  register long x8 asm("x8") = number;
  register long x0 asm("x0") = a0;
  register long x1 asm("x1") = a1;
  register long x2 asm("x2") = a2;
  register long x3 asm("x3") = a3;
  asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
  return x0; // >= 0 on success, -errno on failure
}
#else
long rawSyscall(long number, long a0, long a1, long a2, long a3) {
  long result = syscall(number, a0, a1, a2, a3);
  return result < 0 ? -errno : result;
}
#endif

long sysFaccessat(const char* path) {
  return rawSyscall(__NR_faccessat, AT_FDCWD, reinterpret_cast<long>(path), F_OK, 0);
}

long sysOpenat(const char* path) {
  return rawSyscall(__NR_openat, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0);
}

long sysRead(long fd, char* buffer, size_t size) {
  return rawSyscall(__NR_read, fd, reinterpret_cast<long>(buffer), static_cast<long>(size), 0);
}

void sysClose(long fd) {
  rawSyscall(__NR_close, fd, 0, 0, 0);
}

std::string toStdString(JNIEnv* env, jstring value) {
  const char* chars = env->GetStringUTFChars(value, nullptr);
  std::string result(chars ? chars : "");
  if (chars) env->ReleaseStringUTFChars(value, chars);
  return result;
}

} // namespace

extern "C" {

// Exists (even if unreadable) → true. Uses faccessat(F_OK), which needs only
// search permission on the parent directories, matching File.exists().
JNIEXPORT jboolean JNICALL
Java_com_margelo_nitro_rsnativekit_security_util_NativeChecks_pathExists(JNIEnv* env, jclass, jstring path) {
  std::string nativePath = toStdString(env, path);
  return sysFaccessat(nativePath.c_str()) == 0 ? JNI_TRUE : JNI_FALSE;
}

// Whole file as a Java string (bytes decoded as ISO-8859-1 so binary content
// can't fail UTF-8 decoding), or null when it can't be opened.
JNIEXPORT jstring JNICALL
Java_com_margelo_nitro_rsnativekit_security_util_NativeChecks_readFile(JNIEnv* env, jclass, jstring path) {
  std::string nativePath = toStdString(env, path);
  long fd = sysOpenat(nativePath.c_str());
  if (fd < 0) return nullptr;

  std::string content;
  char buffer[16 * 1024];
  while (content.size() < kMaxFileBytes) {
    long count = sysRead(fd, buffer, sizeof(buffer));
    if (count == -EINTR) continue;
    if (count <= 0) break;
    content.append(buffer, static_cast<size_t>(count));
  }
  sysClose(fd);

  // ISO-8859-1 → UTF-16 is 1:1, so build the jchar array directly.
  std::u16string utf16(content.size(), u'\0');
  for (size_t i = 0; i < content.size(); ++i) {
    utf16[i] = static_cast<char16_t>(static_cast<unsigned char>(content[i]));
  }
  return env->NewString(reinterpret_cast<const jchar*>(utf16.data()), static_cast<jsize>(utf16.size()));
}

// System property value ("" when unset), read from the property area in this
// process rather than by running `getprop`, so a hooked or replaced getprop
// binary — or a hook on android.os.SystemProperties — doesn't see the read.
JNIEXPORT jstring JNICALL
Java_com_margelo_nitro_rsnativekit_security_util_NativeChecks_readProperty(JNIEnv* env, jclass, jstring name) {
  std::string nativeName = toStdString(env, name);
  char value[PROP_VALUE_MAX] = {0};
  __system_property_get(nativeName.c_str(), value);
  return env->NewStringUTF(value);
}

} // extern "C"
