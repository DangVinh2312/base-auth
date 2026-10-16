import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { test, type TestContext } from 'node:test';
import { waitForHttpStartup } from './http-startup.helper.ts';

function launch(t: TestContext, script: string): ChildProcess {
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = once(child, 'exit');
    child.kill('SIGKILL');
    await exited;
  });
  return child;
}

async function endpoint(child: ChildProcess, signal: AbortSignal): Promise<string> {
  const message: unknown = await once(child, 'message', { signal });
  assert.ok(Array.isArray(message));
  const url: unknown = message[0];
  assert.ok(typeof url === 'string');
  return url;
}

test(
  'HTTP startup survives more than 150 failed probes within the test deadline',
  { timeout: 20_000 },
  async (t) => {
    const child = launch(
      t,
      `
    import { createServer } from 'node:http';
    let requests = 0;
    const server = createServer((request, response) => {
      if (++requests <= 151) request.socket.destroy();
      else response.end('ready');
    });
    server.listen(0, '127.0.0.1', () => process.send('http://127.0.0.1:' + server.address().port));
  `,
    );
    const response = await waitForHttpStartup(child, await endpoint(child, t.signal), t.signal);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'ready');
  },
);

const stalledServer = `
  import { createServer } from 'node:http';
  process.on('message', () => process.kill(process.pid, 'SIGTERM'));
  const server = createServer(() => process.send('request-started'));
  server.listen(0, '127.0.0.1', () => process.send('http://127.0.0.1:' + server.address().port));
`;

test('a process signal aborts an in-flight startup probe', { timeout: 5_000 }, async (t) => {
  const child = launch(t, stalledServer);
  const url = await endpoint(child, t.signal);
  const requested = once(child, 'message', { signal: t.signal });
  const rejected = assert.rejects(waitForHttpStartup(child, url, t.signal), /signal=SIGTERM/);
  await requested;
  child.send('exit');
  await rejected;
});

test('the test deadline aborts an in-flight startup probe', { timeout: 5_000 }, async (t) => {
  const child = launch(t, stalledServer);
  const url = await endpoint(child, t.signal);
  const requested = once(child, 'message', { signal: t.signal });
  const deadline = new AbortController();
  const rejected = assert.rejects(
    waitForHttpStartup(child, url, AbortSignal.any([t.signal, deadline.signal])),
    /startup deadline/,
  );
  await requested;
  deadline.abort(new Error('startup deadline'));
  await rejected;
});

test(
  'HTTP startup returns a non-success response for the caller to reject',
  { timeout: 5_000 },
  async (t) => {
    const child = launch(
      t,
      `
    import { createServer } from 'node:http';
    const server = createServer((request, response) => {
      response.writeHead(503);
      response.end('unavailable');
    });
    server.listen(0, '127.0.0.1', () => process.send('http://127.0.0.1:' + server.address().port));
  `,
    );
    const response = await waitForHttpStartup(child, await endpoint(child, t.signal), t.signal);
    assert.equal(response.status, 503);
    assert.equal(await response.text(), 'unavailable');
  },
);

test('an already exited process fails startup without polling', { timeout: 5_000 }, async (t) => {
  const child = launch(t, 'process.exit(7)');
  await once(child, 'exit', { signal: t.signal });
  await assert.rejects(waitForHttpStartup(child, 'http://127.0.0.1:1', t.signal), /code=7/);
});
