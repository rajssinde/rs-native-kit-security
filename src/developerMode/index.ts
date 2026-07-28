import { getNativeSecurity } from '../specs/nativeSecurity';

/** Android: `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`. Not applicable on iOS. */
export function isDeveloperModeEnabled(): Promise<boolean> {
  return getNativeSecurity().isDeveloperModeEnabled();
}

/** Android: `Settings.Global.ADB_ENABLED`. Not applicable on iOS. */
export function isUsbDebuggingEnabled(): Promise<boolean> {
  return getNativeSecurity().isUsbDebuggingEnabled();
}

/** Cross-platform: native debugger/ptrace attach detection. */
export function isDebuggerAttached(): Promise<boolean> {
  return getNativeSecurity().isDebuggerAttached();
}

/** Android: `Settings.Secure.ALLOW_MOCK_LOCATION` / mock-location-app detection. */
export function isMockLocationEnabled(): Promise<boolean> {
  return getNativeSecurity().isMockLocationEnabled();
}
