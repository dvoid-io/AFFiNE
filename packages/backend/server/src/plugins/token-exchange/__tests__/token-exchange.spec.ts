import test from 'ava';
import type { Request, Response } from 'express';
import Sinon from 'sinon';

import type { Config, EventBus } from '../../../base';
import type { Models } from '../../../models';
import { TokenExchangeController } from '../controller';
import { TokenExchangeService } from '../service';
import type { OidcAccessTokenVerifier } from '../verifier';

// Unit-test the seam in isolation. Identity joins on the Zitadel `sub` via the
// ConnectedAccount map (the same the OIDC login uses):
//   - resolve: getConnectedAccount(sub) → user (no id_token, no email)
//   - provision: sub unlinked + id_token → fulfill(email) + createConnectedAccount
// and the controller enforces the trusted-proxy secret, the inert gate, and the
// required subject_token / optional actor_token before delegating.

const GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
const OIDC = 'oidc';

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

function makeBody(subjectToken: string, actorToken?: string) {
  return {
    grant_type: GRANT,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
    ...(actorToken
      ? { actor_token: actorToken, actor_token_type: ID_TOKEN_TYPE }
      : {}),
  };
}

function makeVerifier(configured: boolean) {
  return { configured } as unknown as OidcAccessTokenVerifier;
}

function verifierStub(opts: {
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

function modelsStub(opts: {
  connectedAccount?: { userId: string } | null;
  userByEmail?: { id: string } | null;
  fulfillId?: string;
}) {
  const getConnectedAccount = Sinon.stub().resolves(
    opts.connectedAccount ?? null
  );
  const getUserByEmail = Sinon.stub().resolves(opts.userByEmail ?? null);
  const fulfill = Sinon.stub().resolves({ id: opts.fulfillId ?? 'affine-new' });
  const createConnectedAccount = Sinon.stub().resolves({});
  return {
    models: {
      user: {
        getConnectedAccount,
        getUserByEmail,
        fulfill,
        createConnectedAccount,
      },
    } as unknown as Models,
    getConnectedAccount,
    getUserByEmail,
    fulfill,
    createConnectedAccount,
  };
}

test('exchange: sub with a ConnectedAccount resolves WITHOUT an id_token', async t => {
  const verifier = verifierStub({
    accessClaims: { sub: 'sub-1', jti: 'jti-1' },
  });
  const m = modelsStub({ connectedAccount: { userId: 'affine-user-42' } });
  const event = makeEvent();

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({}),
    event
  );
  const identity = await service.exchange('access.tok');

  t.true(m.getConnectedAccount.calledOnceWith(OIDC, 'sub-1'));
  t.false((verifier.verifyIdTokenEmail as Sinon.SinonStub).called);
  t.false(m.fulfill.called);
  t.false(m.createConnectedAccount.called);
  t.deepEqual(identity, { userId: 'affine-user-42', method: 'oauth' });
  t.true(
    event.emit.calledOnceWith('tokenExchange.identityMinted', {
      userId: 'affine-user-42',
      tokenSub: 'sub-1',
      tokenJti: 'jti-1',
    })
  );
});

test('exchange: unlinked sub + id_token provisions and links the user', async t => {
  const verifier = verifierStub({
    accessClaims: { sub: 'sub-new', jti: 'jti-n' },
    identity: { email: 'agent@affine.pro', name: 'Agent User' },
  });
  const m = modelsStub({
    connectedAccount: null,
    userByEmail: null,
    fulfillId: 'affine-user-99',
  });

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({}),
    makeEvent()
  );
  const identity = await service.exchange('access.tok', 'id.tok');

  t.true(
    (verifier.verifyIdTokenEmail as Sinon.SinonStub).calledOnceWith(
      'id.tok',
      'sub-new'
    )
  );
  t.is(m.fulfill.firstCall.args[0], 'agent@affine.pro');
  t.deepEqual(m.createConnectedAccount.firstCall.args[0], {
    userId: 'affine-user-99',
    provider: OIDC,
    providerAccountId: 'sub-new',
    accessToken: 'access.tok',
  });
  t.deepEqual(identity, { userId: 'affine-user-99', method: 'oauth' });
});

test('exchange: unlinked sub + existing email-user links the sub (backfill)', async t => {
  const verifier = verifierStub({
    accessClaims: { sub: 'sub-legacy' },
    identity: { email: 'legacy@affine.pro', name: undefined },
  });
  // fulfill upserts → returns the existing email-created user; we then link sub.
  const m = modelsStub({
    connectedAccount: null,
    userByEmail: { id: 'affine-user-7' },
    fulfillId: 'affine-user-7',
  });

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({}),
    makeEvent()
  );
  const identity = await service.exchange('access.tok', 'id.tok');

  t.is(identity.userId, 'affine-user-7');
  t.is(
    m.createConnectedAccount.firstCall.args[0].providerAccountId,
    'sub-legacy'
  );
  t.is(m.createConnectedAccount.firstCall.args[0].userId, 'affine-user-7');
});

test('exchange: unlinked sub with NO id_token is rejected (not provisioned)', async t => {
  const verifier = verifierStub({ accessClaims: { sub: 'sub-unprovisioned' } });
  const m = modelsStub({ connectedAccount: null });

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({}),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok'));
  t.false((verifier.verifyIdTokenEmail as Sinon.SinonStub).called);
  t.false(m.fulfill.called);
});

test('exchange: access token without a sub is rejected', async t => {
  const verifier = verifierStub({ accessClaims: { jti: 'no-sub' } });
  const m = modelsStub({ connectedAccount: { userId: 'x' } });

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({}),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok', 'id.tok'));
  t.false(m.getConnectedAccount.called);
});

test('exchange: id_token email resolution failure propagates (no provisioning)', async t => {
  const verifier = verifierStub({
    accessClaims: { sub: 'sub-1' },
    idTokenThrows: true,
  });
  const m = modelsStub({ connectedAccount: null });

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({}),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok', 'id.tok'));
  t.false(m.fulfill.called);
});

test('exchange: new user + allowSignupForOauth=false is forbidden', async t => {
  const verifier = verifierStub({
    accessClaims: { sub: 'sub-new' },
    identity: { email: 'new@affine.pro' },
  });
  const m = modelsStub({ connectedAccount: null, userByEmail: null });

  const service = new TokenExchangeService(
    verifier,
    m.models,
    makeConfig({ allowSignupForOauth: false }),
    makeEvent()
  );

  await t.throwsAsync(service.exchange('access.tok', 'id.tok'));
  t.false(m.fulfill.called);
});

test('controller: resolution body (no actor_token) → exchange(subject, undefined)', async t => {
  const identity = { userId: 'affine-user-42', method: 'oauth' as const };
  const issue = Sinon.stub().resolves({
    userId: 'affine-user-42',
    sessionId: 'sess-abc',
  });
  const tokenExchange = { exchange: Sinon.stub().resolves(identity) } as any;

  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue } as any,
    tokenExchange,
    makeVerifier(true)
  );
  const sent: unknown[] = [];
  const res = { send: (b: unknown) => sent.push(b) } as unknown as Response;

  await controller.exchange(
    {} as Request,
    res,
    makeBody('inbound.jws.token'),
    'top-secret'
  );

  t.true(tokenExchange.exchange.calledOnceWith('inbound.jws.token', undefined));
  t.true(issue.calledOnce);
  t.deepEqual(sent[0], {
    access_token: 'sess-abc',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
  });
});

test('controller: provisioning body (with actor_token) → exchange(subject, actor)', async t => {
  const identity = { userId: 'affine-user-42', method: 'oauth' as const };
  const issue = Sinon.stub().resolves({
    userId: 'affine-user-42',
    sessionId: 'sess-abc',
  });
  const tokenExchange = { exchange: Sinon.stub().resolves(identity) } as any;

  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue } as any,
    tokenExchange,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await controller.exchange(
    {} as Request,
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
});

test('controller: inert (NotFound) when trusted-proxy secret is unconfigured', async t => {
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: '' }),
    { issue: Sinon.stub() } as any,
    { exchange } as any,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), 'anything')
  );
  t.false(exchange.called);
});

test('controller: inert (NotFound) when OIDC verifier is not configured', async t => {
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue: Sinon.stub() } as any,
    { exchange } as any,
    makeVerifier(false)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), 'top-secret')
  );
  t.false(exchange.called);
});

test('controller: wrong/missing trusted-proxy secret is rejected before any work', async t => {
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue: Sinon.stub() } as any,
    { exchange } as any,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), undefined)
  );
  await t.throwsAsync(
    controller.exchange({} as Request, res, makeBody('t'), 'wrong')
  );
  t.false(exchange.called);
});

test('controller: malformed body (missing subject_token / wrong grant_type) rejected', async t => {
  const exchange = Sinon.stub();
  const controller = new TokenExchangeController(
    makeConfig({ trustedProxySecret: 'top-secret' }),
    { issue: Sinon.stub() } as any,
    { exchange } as any,
    makeVerifier(true)
  );
  const res = { send: Sinon.stub() } as unknown as Response;

  await t.throwsAsync(
    controller.exchange(
      {} as Request,
      res,
      { grant_type: GRANT, subject_token_type: ACCESS_TOKEN_TYPE },
      'top-secret'
    )
  );
  await t.throwsAsync(
    controller.exchange(
      {} as Request,
      res,
      {
        grant_type: 'authorization_code',
        subject_token: 't',
        subject_token_type: ACCESS_TOKEN_TYPE,
      },
      'top-secret'
    )
  );
  t.false(exchange.called);
});
