import { NitroModules } from 'react-native-nitro-modules';
import type { Security } from './Security.nitro';

const SecurityHybridObject =
  NitroModules.createHybridObject<Security>('Security');

export function multiply(a: number, b: number): number {
  return SecurityHybridObject.multiply(a, b);
}
