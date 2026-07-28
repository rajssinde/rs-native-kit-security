import { NitroModules } from 'react-native-nitro-modules';
import type { Security } from '../Security.nitro';

export const isNativeSecuritySupported = true;

let instance: Security | undefined;

export function getNativeSecurity(): Security {
  if (!instance) {
    instance = NitroModules.createHybridObject<Security>('Security');
  }
  return instance;
}
