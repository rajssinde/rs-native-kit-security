import { describe, expect, it, jest } from '@jest/globals';
import { SecurityEventEmitter } from '../utils/eventEmitter';
import type { SecurityEvent } from '../types';

const EVENT: SecurityEvent = {
  type: 'ROOT_DETECTED',
  message: 'root detected',
  timestamp: 1,
};

describe('SecurityEventEmitter', () => {
  it('delivers emitted events to all registered listeners', () => {
    const emitter = new SecurityEventEmitter();
    const a = jest.fn();
    const b = jest.fn();
    emitter.add(a);
    emitter.add(b);

    emitter.emit(EVENT);

    expect(a).toHaveBeenCalledWith(EVENT);
    expect(b).toHaveBeenCalledWith(EVENT);
  });

  it('add() returns an unsubscribe function', () => {
    const emitter = new SecurityEventEmitter();
    const listener = jest.fn();
    const unsubscribe = emitter.add(listener);

    unsubscribe();
    emitter.emit(EVENT);

    expect(listener).not.toHaveBeenCalled();
  });

  it('remove() detaches a specific listener', () => {
    const emitter = new SecurityEventEmitter();
    const listener = jest.fn();
    emitter.add(listener);
    emitter.remove(listener);
    emitter.emit(EVENT);
    expect(listener).not.toHaveBeenCalled();
  });

  it('clear() detaches every listener', () => {
    const emitter = new SecurityEventEmitter();
    const a = jest.fn();
    const b = jest.fn();
    emitter.add(a);
    emitter.add(b);
    emitter.clear();
    emitter.emit(EVENT);
    expect(a).not.toHaveBeenCalled();
    expect(b).not.toHaveBeenCalled();
    expect(emitter.size).toBe(0);
  });

  it('isolates a throwing listener from the rest', () => {
    const emitter = new SecurityEventEmitter();
    const throwing = jest.fn(() => {
      throw new Error('boom');
    });
    const healthy = jest.fn();
    const consoleSpy = jest
      .spyOn(console, 'error')
      .mockImplementation(() => {});

    emitter.add(throwing);
    emitter.add(healthy);
    emitter.emit(EVENT);

    expect(healthy).toHaveBeenCalledWith(EVENT);
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('reports the number of active listeners via size', () => {
    const emitter = new SecurityEventEmitter();
    expect(emitter.size).toBe(0);
    emitter.add(() => {});
    expect(emitter.size).toBe(1);
  });
});
