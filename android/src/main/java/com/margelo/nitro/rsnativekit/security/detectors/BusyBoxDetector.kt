package com.margelo.nitro.rsnativekit.security.detectors

import com.margelo.nitro.rsnativekit.security.util.ShellUtils

/** BusyBox is a legitimate embedded-Linux tool, but its presence on a stock Android device is a root/custom-ROM signal. */
internal class BusyBoxDetector {
  fun isDetected(): Boolean {
    return ShellUtils.binaryExistsOnCommonPaths("busybox") ||
      ShellUtils.binaryExistsOnPath("busybox") ||
      ShellUtils.exec(arrayOf("busybox")) != null
  }
}