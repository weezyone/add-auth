import type { JWTPayload } from './jwt';

declare global {
  namespace Express {
    interface User extends JWTPayload {}
  }
}

export {};
