package com.margelo.nitro.rsnativekit.security.detectors

import android.content.pm.PackageManager

/**
 * Every third-party package the detectors look up by name.
 *
 * On Android 11+ (API 30) package visibility filtering makes
 * `getPackageInfo()` throw `NameNotFoundException` for any package the app
 * hasn't declared in a manifest `<queries>` block, so every name here MUST
 * also appear in `src/main/AndroidManifest.xml` — otherwise its check silently
 * reports "not installed". `KnownPackagesManifestTest` enforces this.
 */
internal object KnownPackages {
  val ROOT_MANAGERS = arrayOf(
    "com.topjohnwu.magisk",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "me.phh.superuser",
    "com.geohot.towelroot",
    "com.ramdroid.appquarantine"
  )

  const val MAGISK = "com.topjohnwu.magisk"

  val XPOSED = arrayOf(
    "de.robv.android.xposed.installer",
    "org.meowcat.edxposed.manager",
    "com.solohsu.android.edxp.manager"
  )

  val LSPOSED = arrayOf(
    "org.lsposed.manager"
  )

  const val SUBSTRATE = "com.saurik.substrate"

  val EMULATORS = arrayOf(
    "com.genymotion.genyd", // Genymotion
    "com.bluestacks", // BlueStacks
    "com.bluestacks.home",
    "com.vphone.launcher", // Nox
    "com.bignox.app",
    "com.microvirt.launcher", // MEmu
    "com.microvirt.market",
    "com.ldmnq.launcher3" // LDPlayer
  )

  val MOCK_LOCATION_APPS = arrayOf(
    "com.lexa.fakegps",
    "com.incorporateapps.fakegps.fre",
    "com.blogspot.newapphorizons.fakegps",
    "io.github.jsonstat.fakelocation"
  )

  val OVERLAY_ABUSE = arrayOf(
    "com.baiduAppSearch.searchbox",
    "com.gtp.nextlauncher.overlay",
    "com.android.systemui.overlay.fake"
  )

  val ALL: List<String> =
    (ROOT_MANAGERS + MAGISK + XPOSED + LSPOSED + SUBSTRATE + EMULATORS + MOCK_LOCATION_APPS + OVERLAY_ABUSE)
      .distinct()

  fun isAnyInstalled(pm: PackageManager, packages: Array<String>): Boolean {
    return packages.any { isInstalled(pm, it) }
  }

  fun isInstalled(pm: PackageManager, packageName: String): Boolean {
    return try {
      pm.getPackageInfo(packageName, 0)
      true
    } catch (_: PackageManager.NameNotFoundException) {
      false
    }
  }
}
