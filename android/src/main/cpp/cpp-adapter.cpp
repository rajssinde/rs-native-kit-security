#include <jni.h>
#include "rsnativekit_securityOnLoad.hpp"

#include <fbjni/fbjni.h>


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, []() {
    margelo::nitro::rsnativekit_security::registerAllNatives();
  });
}