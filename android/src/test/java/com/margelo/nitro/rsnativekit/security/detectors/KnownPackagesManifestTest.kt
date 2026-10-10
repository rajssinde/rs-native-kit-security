package com.margelo.nitro.rsnativekit.security.detectors

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Guards against a detector's package list drifting from the manifest's
 * `<queries>` block — a missing entry makes that check silently report
 * "not installed" on Android 11+.
 */
class KnownPackagesManifestTest {

  private fun queriedPackages(): Set<String> {
    // Gradle runs unit tests with the module directory (android/) as the working directory.
    val manifest = File("src/main/AndroidManifest.xml").readText()
    val queries = manifest.substringAfter("<queries>").substringBefore("</queries>")
    return Regex("""<package\s+android:name="([^"]+)"""").findAll(queries).map { it.groupValues[1] }.toSet()
  }

  @Test
  fun `every package a detector looks up is declared in the manifest queries`() {
    assertEquals(emptySet<String>(), KnownPackages.ALL.toSet() - queriedPackages())
  }

  @Test
  fun `the manifest queries no packages that no detector uses`() {
    assertEquals(emptySet<String>(), queriedPackages() - KnownPackages.ALL.toSet())
  }
}
