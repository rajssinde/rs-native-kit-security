/** Every verification failure carries a stable, machine-readable `code`. */
export class AttestationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(`[${code}] ${message}`);
    this.name = 'AttestationError';
    this.code = code;
  }
}
