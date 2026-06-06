import { HttpStatus } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import type { TestFn } from 'ava';
import ava from 'ava';
import Sinon from 'sinon';
import supertest from 'supertest';

import { AppModule } from '../../app.module';
import { ConfigFactory } from '../../base';
import { ConfigModule } from '../../base/config';
import { AuthService } from '../../core/auth/service';
import { OidcAccessTokenVerifier } from '../../plugins/token-exchange/verifier';
import { createTestingApp, TestingApp } from '../utils';

// e2e for the RFC 8693 token-exchange endpoint. The external OIDC provider is
// stubbed (no live IdP needed): we override `OidcAccessTokenVerifier` so its
// `configured` flag and `verify()` claims are controllable, while session
// minting, user provisioning, the signup gate, and cookie replay all run
// through the real app + database.

const GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const SECRET_HEADER = 'x-affine-trusted-proxy-secret';
const TRUSTED_PROXY_SECRET = 'integration-trusted-proxy-secret';

const test = ava as TestFn<{
  app: TestingApp;
  verifier: {
    configured: boolean;
    verify: Sinon.SinonStub;
  };
  db: PrismaClient;
}>;

test.before(async t => {
  // A controllable stand-in for the JWKS verifier — replaces the network /
  // discovery surface only; everything downstream is the real plugin.
  const verifier = {
    configured: true,
    verify: Sinon.stub(),
  };

  const app = await createTestingApp({
    imports: [
      ConfigModule.override({
        oauth: {
          providers: {
            oidc: {
              clientId: 'oidc-client-id',
              clientSecret: 'oidc-client-secret',
              issuer: 'https://issuer.affine.dev',
              args: {},
            },
          },
        },
      }),
      AppModule,
    ],
    tapModule: m => {
      m.overrideProvider(OidcAccessTokenVerifier).useValue(verifier);
    },
  });

  t.context.app = app;
  t.context.verifier = verifier;
  t.context.db = app.get(PrismaClient);
});

test.beforeEach(async t => {
  Sinon.reset();
  t.context.verifier.configured = true;
  await t.context.app.initTestingDB();
  // opt the endpoint in for the default case; individual tests can override.
  t.context.app.get(ConfigFactory).override({
    tokenExchange: {
      trustedProxySecret: TRUSTED_PROXY_SECRET,
      audience: 'affine-api',
    },
    auth: { allowSignupForOauth: true },
  });
});

test.after.always(async t => {
  await t.context.app.close();
});

function exchange(app: TestingApp, secret?: string, body?: unknown) {
  const req = supertest(app.getHttpServer()).post('/api/auth/token-exchange');
  if (secret !== undefined) {
    req.set(SECRET_HEADER, secret);
  }
  return req.send(
    body ?? {
      grant_type: GRANT,
      subject_token: 'inbound.jws.token',
      subject_token_type: TOKEN_TYPE,
    }
  );
}

test('inert (404) when trusted-proxy secret is unconfigured', async t => {
  const { app } = t.context;
  app.get(ConfigFactory).override({
    tokenExchange: { trustedProxySecret: '', audience: '' },
  });

  await exchange(app, TRUSTED_PROXY_SECRET).expect(HttpStatus.NOT_FOUND);
  t.pass();
});

test('inert (404) when OIDC provider is not configured', async t => {
  const { app, verifier } = t.context;
  verifier.configured = false;

  await exchange(app, TRUSTED_PROXY_SECRET).expect(HttpStatus.NOT_FOUND);
  t.pass();
});

test('rejects missing trusted-proxy secret', async t => {
  const { app, verifier } = t.context;
  verifier.verify.resolves({ email: 'should-not-reach@affine.pro' });

  await exchange(app, undefined).expect(HttpStatus.FORBIDDEN);
  t.false(verifier.verify.called);
});

test('rejects wrong trusted-proxy secret', async t => {
  const { app, verifier } = t.context;
  verifier.verify.resolves({ email: 'should-not-reach@affine.pro' });

  await exchange(app, 'wrong-secret').expect(HttpStatus.FORBIDDEN);
  t.false(verifier.verify.called);
});

test('rejects invalid/expired token (verify throws)', async t => {
  const { app, verifier } = t.context;
  // mirrors the verifier's failure surface for bad signature / expiry / aud.
  const { InvalidAuthState } = await import('../../base');
  verifier.verify.rejects(new InvalidAuthState());

  await exchange(app, TRUSTED_PROXY_SECRET).expect(HttpStatus.BAD_REQUEST);
  t.true(verifier.verify.calledOnce);
});

test('rejects malformed RFC 8693 body', async t => {
  const { app, verifier } = t.context;
  verifier.verify.resolves({ email: 'should-not-reach@affine.pro' });

  await exchange(app, TRUSTED_PROXY_SECRET, {
    grant_type: 'authorization_code',
    subject_token: 'x',
    subject_token_type: TOKEN_TYPE,
  }).expect(HttpStatus.BAD_REQUEST);
  t.false(verifier.verify.called);
});

test('valid token mints a session and provisions the user', async t => {
  const { app, verifier, db } = t.context;
  const email = 'provisioned-user@affine.pro';
  verifier.verify.resolves({
    sub: 'oidc-sub-1',
    jti: 'jti-1',
    email,
    name: 'Provisioned User',
  });

  const res = await exchange(app, TRUSTED_PROXY_SECRET).expect(HttpStatus.OK);

  // RFC 8693 §2.2.1 response shape.
  t.is(
    res.body.issued_token_type,
    'urn:ietf:params:oauth:token-type:access_token'
  );
  t.is(res.body.token_type, 'Bearer');
  t.truthy(res.body.access_token);

  // user was provisioned (signup gate open).
  const user = await db.user.findFirst({ where: { email } });
  t.truthy(user);

  // the issued access_token IS the affine_session cookie value — replay it.
  const sessionId = res.body.access_token as string;
  const sessionRes = await supertest(app.getHttpServer())
    .get('/api/auth/session')
    .set('Cookie', `${AuthService.sessionCookieName}=${sessionId}`)
    .expect(HttpStatus.OK);
  t.truthy(sessionRes.body.user);
  t.is(sessionRes.body.user.email, email);
});

test('respects signup gate: new user rejected when allowSignupForOauth=false', async t => {
  const { app, verifier, db } = t.context;
  app.get(ConfigFactory).override({
    auth: { allowSignupForOauth: false },
  });
  const email = 'gated-new-user@affine.pro';
  verifier.verify.resolves({ sub: 'oidc-sub-2', email });

  await exchange(app, TRUSTED_PROXY_SECRET).expect(HttpStatus.FORBIDDEN);

  const user = await db.user.findFirst({ where: { email } });
  t.is(user, null);
});

test('audience mismatch is rejected (verifier rejects aud-failed token)', async t => {
  const { app, verifier } = t.context;
  // the verifier enforces `aud` via jwtVerify; a mismatch surfaces as the same
  // InvalidAuthState. We model that here by having verify reject.
  const { InvalidAuthState } = await import('../../base');
  verifier.verify.rejects(new InvalidAuthState());

  await exchange(app, TRUSTED_PROXY_SECRET).expect(HttpStatus.BAD_REQUEST);
  t.true(verifier.verify.calledOnce);
});
