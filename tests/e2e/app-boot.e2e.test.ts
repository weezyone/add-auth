import net from 'net';
import request from 'supertest';
import { setupInfrastructure, resetState, teardownInfrastructure, loadApp } from './helpers';

function isPortListening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
}

describe('app boot (NODE_ENV=test)', () => {
  beforeAll(setupInfrastructure);
  beforeEach(resetState);
  afterAll(teardownInfrastructure);

  it('can be imported without crashing and serves the root route', async () => {
    const app = loadApp();
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Add-Auth API');
  });

  it('does not bind a port as a side effect of being imported under test', async () => {
    loadApp();
    // give a would-be listen() a tick to bind
    await new Promise((r) => setTimeout(r, 200));
    expect(await isPortListening(Number(process.env.PORT))).toBe(false);
  });
});
