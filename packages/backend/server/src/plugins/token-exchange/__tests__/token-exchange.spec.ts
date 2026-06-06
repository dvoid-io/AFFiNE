import test from 'ava';
import type { Request, Response } from 'express';
import Sinon from 'sinon';

import type { Config, EventBus } from '../../../base';
import type { Models } from '../../../models';
import { TokenExchangeController } from '../controller';
import { TokenExchangeService } from '../service';
import type { OidcAccessTokenVerifier } from '../verifier';

// Unit-test the seam in isolation: mock the JWKS verify + the user model, then
// assert verify → (signup gate) → fulfill(email) → identity, and that the
// controller enforces the trusted-proxy secret (and inert-when-unconfigured
// gate) before handing the identity to SessionIssuer.issue.

const GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

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

function makeBody(subjectToken: string) {
  return {
    grant_type: GRANT,
    subject_token: subjectToken,
    subject_token_type: TOKEN_TYPE,
  };
}

function makeVerifier(configured: boolean) {
  return { configured } as unknown as OidcAccessTokenVerifier;
}

test('exchange: verified email resolves user via fulfill and emits audit event', async t => {
  const verifier = {
    verify: Sinon.stub().resolves({
      sub: 'oidc-sub-123',
      jti: 'jti-1',
      email: 'agent-user@affine.pro',
      name: 'Agent User',
    }),
  } as unknown as OidcAccessTokenVerifier;

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
  const identity = await service.exchange('inbound.jws.token');

  t.true(
    (verifier.verify as Sinon.SinonStub).calledOnceWith('inbound.jws.token')
  );
  t.is(fulfill.firstCall.args[0], 'agent-user@affine.pro');
  t.deepEqual(identity, { userId: 'affine-user-42', method: 'oauth' });
  t.true(
    event.emit.calledOnceWith('tokenExchange.identityMinted', {
      userId: 'affine-user-42',
      tokenSub: 'oidc-sub-123',
      tokenJti: 'jti-1',
    })
  );
});

test('exchange: token without a valid email claim is rejected (trust boundary)', async t => {
  const verifier = {
    verify: Sinon.stub().resolves({ sub: 'no-email-sub' }),
  } as unknown as OidcAccessTokenVerifier;
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

  await t.throwsAsync(service.exchange('inbound.jws.token'));
  t.false(fulfill.called);
});

test('exchange: new user + allowSignupForOauth=false is forbidden (no provisioning)', async t => {
  const verifier = {
    verify: Sinon.stub().resolves({ email: 'new-user@affine.pro' }),
  } as unknown as OidcAccessTokenVerifier;
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

  await t.throwsAsync(service.exchange('inbound.jws.token'));
  t.false(fulfill.called);
});

test('exchange: existing user resolves even when allowSignupForOauth=false', async t => {
  const verifier = {
    verify: Sinon.stub().resolves({ email: 'existing@affine.pro' }),
  } as unknown as OidcAccessTokenVerifier;
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

  const identity = await service.exchange('inbound.jws.token');
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
    makeBody('inbound.jws.token'),
    'top-secret'
  );

  t.true(tokenExchange.exchange.calledOnceWith('inbound.jws.token'));
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
      { grant_type: GRANT, subject_token_type: TOKEN_TYPE },
      'top-secret'
    )
  );
  // wrong grant_type
  await t.throwsAsync(
    controller.exchange(
      {} as Request,
      res,
      { grant_type: 'authorization_code', subject_token: 't', subject_token_type: TOKEN_TYPE },
      'top-secret'
    )
  );
  t.false(exchange.called);
  t.false(issue.called);
});
