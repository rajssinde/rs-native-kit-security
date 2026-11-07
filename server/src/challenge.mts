import { randomBytes } from 'node:crypto';

/** A fresh, unguessable challenge (base64url). Bind every attestation to one. */
export function createChallenge(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Issues single-use challenges with a time limit. Replay protection depends
 * on `consume()` succeeding at most once per challenge — back it with a
 * shared store (Redis `SET NX EX` + `GETDEL`, a DB row) when running more
 * than one server instance.
 */
export interface ChallengeStore {
  issue(ttlMs?: number): Promise<string>;
  /** `true` exactly once for a challenge issued and not yet expired. */
  consume(challenge: string): Promise<boolean>;
}

/** In-process `ChallengeStore` for a single server instance, tests and demos. */
export class InMemoryChallengeStore implements ChallengeStore {
  private readonly pending = new Map<string, number>();
  private readonly defaultTtlMs: number;
  private readonly clock: () => number;

  constructor(options: { defaultTtlMs?: number; now?: () => number } = {}) {
    this.defaultTtlMs = options.defaultTtlMs ?? 5 * 60_000;
    this.clock = options.now ?? Date.now;
  }

  async issue(ttlMs = this.defaultTtlMs): Promise<string> {
    this.prune();
    const challenge = createChallenge();
    this.pending.set(challenge, this.clock() + ttlMs);
    return challenge;
  }

  async consume(challenge: string): Promise<boolean> {
    const expiresAt = this.pending.get(challenge);
    this.pending.delete(challenge);
    return expiresAt !== undefined && expiresAt >= this.clock();
  }

  private prune(): void {
    const now = this.clock();
    for (const [challenge, expiresAt] of this.pending) {
      if (expiresAt < now) this.pending.delete(challenge);
    }
  }
}
