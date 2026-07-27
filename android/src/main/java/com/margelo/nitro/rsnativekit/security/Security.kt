package com.margelo.nitro.rsnativekit.security
  
import com.facebook.proguard.annotations.DoNotStrip

@DoNotStrip
class Security : HybridSecuritySpec() {
  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }
}
