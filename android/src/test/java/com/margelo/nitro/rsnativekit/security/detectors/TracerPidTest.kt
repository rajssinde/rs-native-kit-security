package com.margelo.nitro.rsnativekit.security.detectors

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TracerPidTest {

  private fun status(tracerLine: String) = """
    Name:	rsnativekit.example
    State:	S (sleeping)
    Tgid:	4152
    Pid:	4152
    PPid:	640
    $tracerLine
    Uid:	10210	10210	10210	10210
  """.trimIndent()

  @Test
  fun `no tracer is pid 0`() {
    assertEquals(0, tracerPid(status("TracerPid:\t0")))
  }

  @Test
  fun `an attached debugger reports its pid`() {
    assertEquals(9123, tracerPid(status("TracerPid:\t9123")))
  }

  @Test
  fun `a status without TracerPid is an error, not a clean result`() {
    assertThrows(IllegalStateException::class.java) { tracerPid(status("Seccomp:\t2")) }
  }
}
