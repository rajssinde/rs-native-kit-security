import type { SecurityEvent, SecurityEventListener } from '../types';

/**
 * Minimal, dependency-free pub/sub used to fan a single native event
 * callback out to any number of JS listeners registered via
 * `Security.addListener()`.
 */
export class SecurityEventEmitter {
  private readonly listeners = new Set<SecurityEventListener>();

  add(listener: SecurityEventListener): () => void {
    this.listeners.add(listener);
    return () => this.remove(listener);
  }

  remove(listener: SecurityEventListener): void {
    this.listeners.delete(listener);
  }

  clear(): void {
    this.listeners.clear();
  }

  get size(): number {
    return this.listeners.size;
  }

  emit(event: SecurityEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (error) {
        console.error(
          '[@rs-native-kit/security] A SecurityEvent listener threw an error:',
          error
        );
      }
    }
  }
}
