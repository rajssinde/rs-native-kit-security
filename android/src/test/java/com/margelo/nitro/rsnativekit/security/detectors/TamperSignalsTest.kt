package com.margelo.nitro.rsnativekit.security.detectors

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TamperSignalsTest {

  @Test
  fun `recognises the LSPatch component factory stub`() {
    assertTrue(isLsPatchFactory("org.lsposed.lspatch.metaloader.LSPAppComponentFactoryStub"))
  }

  @Test
  fun `ignores stock and absent component factories`() {
    assertFalse(isLsPatchFactory(null))
    assertFalse(isLsPatchFactory("androidx.core.app.CoreComponentFactory"))
  }

  @Test
  fun `recognises LSPatch assets but not ordinary ones`() {
    assertTrue(isLsPatchEntry("assets/lspatch/origin.apk"))
    assertTrue(isLsPatchEntry("assets/lspatch/config.json"))
    assertFalse(isLsPatchEntry("assets/index.android.bundle"))
    assertFalse(isLsPatchEntry("classes.dex"))
  }
}
