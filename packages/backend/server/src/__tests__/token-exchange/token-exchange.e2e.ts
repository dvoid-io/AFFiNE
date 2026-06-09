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
// `configured` flag, `verify()` (access token → sub) and `verifyIdTokenEmail()`
// (id_token → email) are controllable, while ConnectedAccount mapping, session
// minting, provisioning, the signup gate, and cookie replay run through the real
// app + database. Identity joins on the Zitadel `sub`.

const GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
const SECRET_HEADER = 'x-affine-trusted-proxy-secret';
const TRUSTED_PROXY_SECRET = 'integration-trusted-proxy-secret';

const test = ava as TestFn<{
  app: TestingApp;
  verifier: {
    configured: boolean;
    verify: Sinon.SinonStub;
    verifyIdTokenEmail: Sinon.SinonStub;
  };
  db: PrismaClient;
}>;

test.before(async t => {
  const verifier = {
    configured: true,
    verify: Sinon.stub(),
    verifyIdTokenEmail: Sinon.stub(),
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

function exchange(app: TestingApp, secret?: string, body?: object) {
  const req = supertest(app.getHttpServer()).post('/api/auth/token-exchange');
  if (secret !== undefined) {
    req.set(SECRET_HEADER, secret);
  }
  return req.send(body);
}

function provisionBody(subjectToken = 'access.tok') {
  return {
    grant_type: GRANT,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
    actor_token: 'id.tok',
    actor_token_type: ID_TOKEN_TYPE,
  };
}

function resolveBody(subjectToken = 'access.tok') {
  return {
    grant_type: GRANT,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
  };
}

test('inert (404) when trusted-proxy secret is unconfigured', async t => {
  const { app } = t.context;
  app.get(ConfigFactory).override({
    tokenExchange: { trustedProxySecret: '', audience: '' },
  });

  await exchange(app, TRUSTED_PROXY_SECRET, resolveBody()).expect(
    HttpStatus.NOT_FOUND
  );
  t.pass();
});

test('rejects missing/wrong trusted-proxy secret before any work', async t => {
  const { app, verifier } = t.context;
  verifier.verify.resolves({ sub: 'sub-1' });

  await exchange(app, undefined, resolveBody()).expect(HttpStatus.FORBIDDEN);
  await exchange(app, 'wrong', resolveBody()).expect(HttpStatus.FORBIDDEN);
  t.false(verifier.verify.called);
});

test('rejects invalid access token (verify throws)', async t => {
  const { app, verifier } = t.context;
  const { InvalidAuthState } = await import('../../base');
  verifier.verify.rejects(new InvalidAuthState());

  await exchange(app, TRUSTED_PROXY_SECRET, resolveBody()).expect(
    HttpStatus.BAD_REQUEST
  );
  t.true(verifier.verify.calledOnce);
});

test('rejects malformed body (wrong grant_type)', async t => {
  const { app, verifier } = t.context;
  verifier.verify.resolves({ sub: 'sub-1' });

  await exchange(app, TRUSTED_PROXY_SECRET, {
    grant_type: 'authorization_code',
    subject_token: 'x',
    subject_token_type: ACCESS_TOKEN_TYPE,
  }).expect(HttpStatus.BAD_REQUEST);
  t.false(verifier.verify.called);
});

test('unlinked sub with NO id_token is rejected (not provisioned)', async t => {
  const { app, verifier } = t.context;
  verifier.verify.resolves({ sub: 'sub-unprovisioned' });

  await exchange(app, TRUSTED_PROXY_SECRET, resolveBody()).expect(
    HttpStatus.BAD_REQUEST
  );
  t.false(verifier.verifyIdTokenEmail.called);
});

test('provision-then-resolve: id_token provisions + links sub, then sub resolves alone', async t => {
  const { app, verifier, db } = t.context;
  const email = 'provisioned@affine.pro';
  verifier.verify.resolves({ sub: 'sub-stable', jti: 'jti-1' });
  verifier.verifyIdTokenEmail.resolves({ email, name: 'Provisioned User' });

  // 1) Provisioning call (carries id_token) — creates user + ConnectedAccount.
  const provRes = await exchange(
    app,
    TRUSTED_PROXY_SECRET,
    provisionBody()
  ).expect(HttpStatus.OK);
  t.truthy(provRes.body.access_token);
  t.is(verifier.verifyIdTokenEmail.firstCall.args[1], 'sub-stable');

  const user = await db.user.findFirst({ where: { email } });
  t.truthy(user);
  const account = await db.connectedAccount.findFirst({
    where: { provider: 'oidc', providerAccountId: 'sub-stable' },
  });
  t.truthy(account);
  t.is(account?.userId, user?.id);

  // 2) Resolution call (NO id_token) — resolves the same sub via ConnectedAccount.
  verifier.verifyIdTokenEmail.resetHistory();
  const resRes = await exchange(
    app,
    TRUSTED_PROXY_SECRET,
    resolveBody()
  ).expect(HttpStatus.OK);
  t.truthy(resRes.body.access_token);
  t.false(verifier.verifyIdTokenEmail.called); // no id_token path on resolution

  // the session replays to the same user.
  const sessionId = resRes.body.access_token as string;
  const sessionRes = await supertest(app.getHttpServer())
    .get('/api/auth/session')
    .set('Cookie', `${AuthService.sessionCookieName}=${sessionId}`)
    .expect(HttpStatus.OK);
  t.is(sessionRes.body.user.email, email);
});

test('unlinked sub + existing email-user links the sub (backfill)', async t => {
  const { app, verifier, db } = t.context;
  const email = 'legacy@affine.pro';
  // Seed a legacy user created by email with no ConnectedAccount.
  const legacy = await db.user.create({
    data: { email, name: 'Legacy', emailVerifiedAt: new Date() },
  });

  verifier.verify.resolves({ sub: 'sub-legacy' });
  verifier.verifyIdTokenEmail.resolves({ email, name: 'Legacy' });

  await exchange(app, TRUSTED_PROXY_SECRET, provisionBody()).expect(
    HttpStatus.OK
  );

  const account = await db.connectedAccount.findFirst({
    where: { provider: 'oidc', providerAccountId: 'sub-legacy' },
  });
  t.is(account?.userId, legacy.id); // linked, not duplicated
});

test('respects signup gate: new user rejected when allowSignupForOauth=false', async t => {
  const { app, verifier, db } = t.context;
  app.get(ConfigFactory).override({ auth: { allowSignupForOauth: false } });
  const email = 'gated@affine.pro';
  verifier.verify.resolves({ sub: 'sub-gated' });
  verifier.verifyIdTokenEmail.resolves({ email, name: undefined });

  await exchange(app, TRUSTED_PROXY_SECRET, provisionBody()).expect(
    HttpStatus.FORBIDDEN
  );
  const user = await db.user.findFirst({ where: { email } });
  t.is(user, null);
});
