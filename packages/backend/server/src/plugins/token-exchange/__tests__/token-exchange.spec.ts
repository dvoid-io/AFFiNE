import test from 'ava';
import type { Request, Response } from 'express';
import Sinon from 'sinon';

import type { Config, EventBus } from '../../../base';
import type { Models } from '../../../models';
import { TokenExchangeController } from '../controller';
import { TokenExchangeService } from '../service';
import type { OidcAccessTokenVerifier } from '../verifier';

// Unit-test the seam in isolation: mock the JWKS verify + the user model, then
// assert verify(access_token) → id_token email → (signup gate) → fulfill(email)
// → identity, and that the controller enforces the trusted-proxy secret (and
// inert-when-unconfigured gate) and the required RFC 8693 token pair before
// handing the identity to SessionIssuer.issue.

const GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';

function makeConfig(overrides: {
  allowSignupForOauth?: boolean;
  trustedProxySecret?: string;
}): Config {
  return {
    auth: { allowSignupForOauth: overrides.allowSignupForOauth ?? true },
    tokenExchange: {
      trustedProxySecret: overrides.trustedProxySecret ?? 'top-secret',
    },
  } as unknown as Config;
}

function makeEvent(): EventBus & { emit: Sinon.SinonStub } {
  return { emit: Sinon.stub() } as unknown as EventBus & {
    emit: Sinon.SinonStub;
  };
}

function makeBody(subjectToken: string, actorToken = 'inbound.id.token') {
  return {
    grant_type: GRANT,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
    actor_token: actorToken,
    actor_token_type: ID_TOKEN_TYPE,
  };
}

function makeVerifier(configured: boolean) {
  return { configured } as unknown as OidcAccessTokenVerifier;
}

/**
 * A verifier double: `verify` resolves the access-token claims (sub/jti),
 * `verifyIdTokenEmail` resolves the id_token-derived email + name.
 */
function serviceVerifier(opts: {
  accessClaims: Record<string, unknown>;
  identity?: { email: string; name?: string };
  idTokenThrows?: boolean;
}): OidcAccessTokenVerifier {
  const verifyIdTokenEmail = opts.idTokenThrows
    ? Sinon.stub().rejects(new Error('InvalidAuthState'))
    : Sinon.stub().resolves(opts.identity);
  return {
    verify: Sinon.stub().resolves(opts.accessClaims),
    verifyIdTokenEmail,
  } as unknown as OidcAccessTokenVerifier;
}

test('exchange: access sub + id_token email resolves user via fulfill and emits audit', async t => {
  const verifier = serviceVerifier({
    accessClaims: { sub: 'oidc-sub-123', jti: 'jti-1' },
    identity: { email: 'agent-user@affine.pro', name: 'Agent User' },
  });

  const fulfill = Sinon.stub().resolves({ id: 'affine-user-42' });
  const getUserByEmail = Sinon.stub().resolves(null);
  const models = {
    user: { fulfill, getUserByEmail },
  } as unknown as Models;
  const event = makeEvent();

  const service = new TokenExchangeService(
    verifier,
    models,
    makeConfig({}),
    event
  );
  const identity = await service.exchange('access.tok', 'id.tok');

  t.true((verifier.verify as Sinon.SinonStub).calledOnceWith('access.tok'));
  t.true(
    (verifier.verifyIdTokenEmail as Sinon.SinonStub).calledOnceWith(
      'id.tok',
      'oidc-sub-123'
    )
  );
  t.is(fulfill.firstCall.args[0], 'agent-user@affine.pro');
  t.deepEqual(fulfill.firstCall.args[1], { name: 'Agent User' });
  t.deepEqual(identity, { userId: 'affine-user-42', method: 'oauth' });
  t.true(
    event.emit.calledOnceWith('tokenExchange.identityMinted', {
      userId: 'affine-user-42',
      tokenSub: 'oidc-sub-123',
      tokenJti: 'jti-1',
    })
  );
});

test('exchange: access token without a sub is rejected before touching the id_token', async t => {
  const verifier = serviceVerifier({
    accessClaims: { jti: 'no-sub' },
    identity: { email: 'should-not@affine.pro' },
  });
  const fulfill = Sinon.stub().resolves({ id: 'should-not-happen' });
  const models = {
    user: { fulfill, getUserByEmail: Sinon.stub() },
  } as unknown as Models;

  const service = new TokenExchangeService(
    verifier,
    models,
    makeConfig({}),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok', 'id.tok'));
  t.false((verifier.verifyIdTokenEmail as Sinon.SinonStub).called);
  t.false(fulfill.called);
});

test('exchange: id_token email resolution failure propagates (no provisioning)', async t => {
  const verifier = serviceVerifier({
    accessClaims: { sub: 'sub-1' },
    idTokenThrows: true,
  });
  const fulfill = Sinon.stub().resolves({ id: 'should-not-happen' });
  const models = {
    user: { fulfill, getUserByEmail: Sinon.stub() },
  } as unknown as Models;

  const service = new TokenExchangeService(
    verifier,
    models,
    makeConfig({}),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok', 'id.tok'));
  t.false(fulfill.called);
});

test('exchange: new user + allowSignupForOauth=false is forbidden (no provisioning)', async t => {
  const verifier = serviceVerifier({
    accessClaims: { sub: 'sub-1' },
    identity: { email: 'new-user@affine.pro' },
  });
  const fulfill = Sinon.stub().resolves({ id: 'should-not-happen' });
  const getUserByEmail = Sinon.stub().resolves(null);
  const models = {
    user: { fulfill, getUserByEmail },
  } as unknown as Models;

  const service = new TokenExchangeService(
    verifier,
    models,
    makeConfig({ allowSignupForOauth: false }),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok', 'id.tok'));
  t.false(fulfill.called);
});

test('exchange: existing user resolves even when allowSignupForOauth=false', async t => {
  const verifier = serviceVerifier({
    accessClaims: { sub: 'sub-1' },
    identity: { email: 'existing@affine.pro' },
  });
  const fulfill = Sinon.stub().resolves({ id: 'affine-user-7' });
  const getUserByEmail = Sinon.stub().resolves({ id: 'affine-user-7' });
  const models = {
    user: { fulfill, getUserByEmail },
  } as unknown as Models;

  const service = new TokenExchangeService(
    verifier,
    models,
    makeConfig({ allowSignupForOauth: false }),
    makeEvent()
  );

  const identity = await service.exchange('access.tok', 'id.tok');
  t.is(identity.userId, 'affine-user-7');
  t.true(fulfill.calledOnce);
});

test('controller: valid secret + RFC 8693 body → SessionIssuer.issue, returns RFC 8693 response', async t => {
  const identity = { userId: 'affine-user-42', method: 'oauth' as const };
  const issue = Sinon.stub().resolves({
    userId: 'affine-user-42',
    sessionId: 'sess-abc',
  });
  const sessionIssuer = { issue } as any;
  const tokenExchange = { exchange: Sinon.stub().resolves(identity) } as any;

  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    sessionIssuer,
    tokenExchange,
    makeVerifier(true)
  );

  const req = {} as Request;
  const sent: unknown[] = [];
  const res = {
    send: (body: unknown) => sent.push(body),
  } as unknown as Response;

  await controller.exchange(
    req,
    res,
    makeBody('inbound.jws.token', 'inbound.id.token'),
    'top-secret'
  );

  t.true(
    tokenExchange.exchange.calledOnceWith(
      'inbound.jws.token',
      'inbound.id.token'
    )
  );
  t.true(issue.calledOnce);
  t.is(issue.firstCall.args[0], req);
  t.is(issue.firstCall.args[1], res);
  t.deepEqual(issue.firstCall.args[2], identity);
  // RFC 8693 §2.2.1 response: session id surfaced as the issued access token.
  t.deepEqual(sent[0], {
    access_token: 'sess-abc',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
  });
});

test('controller: inert (NotFound) when trusted-proxy secret is unconfigured', async t => {
  const issue = Sinon.stub();
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: '' }),
    { issue } as any,
    { exchange } as any,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), 'anything')
  );
  t.false(exchange.called);
  t.false(issue.called);
});

test('controller: inert (NotFound) when OIDC verifier is not configured', async t => {
  const issue = Sinon.stub();
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue } as any,
    { exchange } as any,
    makeVerifier(false)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), 'top-secret')
  );
  t.false(exchange.called);
  t.false(issue.called);
});

test('controller: wrong/missing trusted-proxy secret is rejected before any work', async t => {
  const issue = Sinon.stub();
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue } as any,
    { exchange } as any,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  // missing secret
  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), undefined)
  );
  // wrong secret
  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), 'wrong')
  );
  t.false(exchange.called);
  t.false(issue.called);
});

test('controller: valid secret but malformed RFC 8693 body is rejected', async t => {
  const issue = Sinon.stub();
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue } as any,
    { exchange } as any,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  // missing subject_token
  await t.throwsAsync(
    controller.exchange(
      {} as Request,
      res,
      {
        grant_type: GRANT,
        subject_token_type: ACCESS_TOKEN_TYPE,
        actor_token: 'id',
        actor_token_type: ID_TOKEN_TYPE,
      },
      'top-secret'
    )
  );
  // missing actor_token (id_token) — no fallback, so this must be rejected
  await t.throwsAsync(
    controller.exchange(
      {} as Request,
      res,
      {
        grant_type: GRANT,
        subject_token: 't',
        subject_token_type: ACCESS_TOKEN_TYPE,
      },
      'top-secret'
    )
  );
  // wrong grant_type
  await t.throwsAsync(
    controller.exchange(
      {} as Request,
      res,
      {
        grant_type: 'authorization_code',
        subject_token: 't',
        subject_token_type: ACCESS_TOKEN_TYPE,
        actor_token: 'id',
        actor_token_type: ID_TOKEN_TYPE,
      },
      'top-secret'
    )
  );
  t.false(exchange.called);
  t.false(issue.called);
});
