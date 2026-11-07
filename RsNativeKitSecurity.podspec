require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

# Nitro's generated bindings are tied to the react-native-nitro-modules runtime: this
# package ships one tree per compatible range (see nitro-compat.json) and picks the
# one matching the app's installed runtime.
nitro_compat = JSON.parse(File.read(File.join(__dir__, "nitro-compat.json")))
nitro_version = begin
  path = `cd "#{__dir__}" && node -p "require.resolve('react-native-nitro-modules/package.json')" 2>/dev/null`.strip
  path.empty? ? nil : JSON.parse(File.read(path))["version"]
rescue StandardError
  nil
end
nitro_tuple = ->(v) { v[/\A\d+\.\d+\.\d+/].split(".").map(&:to_i) }
nitrogen_dir = "generated"
if nitro_version.nil?
  Pod::UI.warn "[@rs-native-kit/security] Could not determine the react-native-nitro-modules version; assuming >= #{nitro_compat["modernFrom"]}."
elsif (nitro_tuple.(nitro_version) <=> nitro_tuple.(nitro_compat["minimum"])) < 0
  raise "[@rs-native-kit/security] react-native-nitro-modules #{nitro_version} is not supported; install #{nitro_compat["minimum"]} or newer."
else
  nitrogen_dir = "generated-legacy" if (nitro_tuple.(nitro_version) <=> nitro_tuple.(nitro_compat["modernFrom"])) < 0
  if (nitro_tuple.(nitro_version) <=> nitro_tuple.(nitro_compat["newestTested"])) > 0
    Pod::UI.warn "[@rs-native-kit/security] react-native-nitro-modules #{nitro_version} is newer than the newest tested version (#{nitro_compat["newestTested"]})."
  end
end

Pod::Spec.new do |s|
  s.name         = "RsNativeKitSecurity"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/rajssinde/rs-native-kit-security.git", :tag => "#{s.version}" }

  s.source_files = [
    "ios/**/*.{swift}",
    "ios/**/*.{h,m,mm}",
    "cpp/**/*.{hpp,cpp}",
  ]
  # Visible to the pod's Swift code via its module (raw-syscall probes).
  s.public_header_files = ["ios/Native/*.h"]
  s.exclude_files = "ios/Tests/**/*"

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'

  load "nitrogen/#{nitrogen_dir}/ios/RsNativeKitSecurity+autolinking.rb"
  add_nitrogen_files(s)

  install_modules_dependencies(s)

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'ios/Tests/**/*.swift'
    # CocoaPods' generated host app has no scene delegate, so UIKit aborts it on iOS 27.
    test_spec.requires_app_host = false
  end
end
