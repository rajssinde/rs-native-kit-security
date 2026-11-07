package com.margelo.nitro.rsnativekit.security.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ShellUtilsTest {

  @Test
  fun `binaryExistsOnCommonPaths returns false for a binary that does not exist`() {
    assertFalse(ShellUtils.binaryExistsOnCommonPaths("definitely-not-a-real-binary-12345"))
  }

  @Test
  fun `binaryExistsOnPath finds an executable that is actually on PATH`() {
    // `sh` is guaranteed to exist on every macOS/Linux CI runner this test executes on.
    assertTrue(ShellUtils.binaryExistsOnPath("sh") || ShellUtils.binaryExistsOnCommonPaths("sh"))
  }

  @Test
  fun `binaryExistsOnPath returns false for a made-up binary name`() {
    assertFalse(ShellUtils.binaryExistsOnPath("definitely-not-a-real-binary-12345"))
  }

  @Test
  fun `exec returns stdout for a simple command`() {
    val output = ShellUtils.exec(arrayOf("echo", "hello-from-shellutils"))
    assertEquals("hello-from-shellutils", output?.trim())
  }

  @Test
  fun `exec returns null for a command that does not exist`() {
    assertNull(ShellUtils.exec(arrayOf("definitely-not-a-real-command-12345")))
  }

  @Test
  fun `exec returns null when the command runs but exits non-zero`() {
    // Mirrors `which su` on a stock device: runs fine, prints nothing, exits 1.
    assertNull(ShellUtils.exec(arrayOf("sh", "-c", "exit 1")))
  }

  @Test
  fun `exec returns output larger than the pipe buffer without deadlocking`() {
    val output = ShellUtils.exec(arrayOf("sh", "-c", "yes a | head -c 200000"), timeoutMs = 5000)
    assertEquals(200_000, output?.length)
  }

  @Test
  fun `exec respects a short timeout instead of hanging forever`() {
    val output = ShellUtils.exec(arrayOf("sleep", "5"), timeoutMs = 100)
    assertNull(output)
  }

  @Test
  fun `isWritable reflects the real filesystem state`() {
    val tempDir = File(System.getProperty("java.io.tmpdir") ?: "/tmp")
    assertTrue(ShellUtils.isWritable(tempDir.path))
    assertFalse(ShellUtils.isWritable("/definitely/not/a/real/path/12345"))
  }

  @Test
  fun `readFileOrNull returns file contents when readable`() {
    val file = File.createTempFile("shellutils-test", ".txt")
    file.writeText("hello")
    try {
      assertEquals("hello", ShellUtils.readFileOrNull(file.path))
    } finally {
      file.delete()
    }
  }

  @Test
  fun `readFileOrNull returns null for a missing file`() {
    assertNull(ShellUtils.readFileOrNull("/definitely/not/a/real/file/12345"))
  }
}
