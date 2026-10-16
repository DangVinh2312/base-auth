import type { ChildProcess } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';

export async function waitForHttpStartup(
  child: ChildProcess,
  url: string,
  signal: AbortSignal,
): Promise<Response> {
  const exited = new AbortController();

  const onExit = () =>
    exited.abort(
      new Error(
        `API exited before HTTP startup (code=${child.exitCode}, signal=${child.signalCode})`,
      ),
    );

  const onError = () => exited.abort(new Error('API process failed before HTTP startup'));

  child.once('exit', onExit);
  child.once('error', onError);
  const waiting = AbortSignal.any([signal, exited.signal]);
  try {
    if (child.exitCode !== null || child.signalCode !== null) onExit();
    // The enclosing test owns the deadline; process failure also cancels an in-flight probe.
    while (true) {
      waiting.throwIfAborted();
      try {
        const response = await fetch(url, { signal: waiting });
        waiting.throwIfAborted();
        return response;
      } catch {
        waiting.throwIfAborted();
      }
      await setTimeout(50, undefined, { signal: waiting });
    }
  } catch (error) {
    waiting.throwIfAborted();
    throw error;
  } finally {
    child.off('exit', onExit);
    child.off('error', onError);
  }
}
