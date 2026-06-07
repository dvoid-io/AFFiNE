import test from 'ava';
import type { JWTPayload } from 'jose';
import Sinon from 'sinon';

import type { Config } from '../../../base';
import { OidcAccessTokenVerifier } from '../verifier';

// Unit-test the verifier's email resolution in isolation. The cryptographic
// verify (`verify`) is stubbed per-test so no JWKS/network is needed there; the
// only network we exercise is the OIDC discovery doc (during setup) and the
// userinfo fallback, both via a stubbed `global.fetch`.

const ISSUER = 'https://issuer.example.com';
const USERINFO = 'https://issuer.example.com/oidc/userinfo';

function makeConfig(args?: { claim_email?: string }): Config {
  return {
    oauth: {
      providers: {
        oidc: {
          clientId: 'client',
          issuer: ISSUER,
          args: args ?? {},
        },
      },
    },
    tokenExchange: { audience: 'affine-api' },
  } as unknown as Config;
}

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => body,
  } as unknown as Response;
}

/**
 * Build a configured verifier: stub `global.fetch` so the discovery fetch in
 * `setup()` resolves the issuer + userinfo_endpoint, then run setup.
 */
async function configuredVerifier(
  config: Config,
  discovery: Record<string, unknown> = {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/oidc/jwks`,
    userinfo_endpoint: USERINFO,
  }
) {
  const fetchStub = Sinon.stub(global, 'fetch');
  fetchStub
    .withArgs(Sinon.match(/well-known\/openid-configuration/))
    .resolves(jsonResponse(discovery));

  const verifier = new OidcAccessTokenVerifier(config);
  await (verifier as unknown as { setup: () => Promise<void> }).setup();
  return { verifier, fetchStub };
}

test.afterEach.always(() => {
  Sinon.restore();
});

test('email present on access token → fast path, no userinfo call', async t => {
  const { verifier, fetchStub } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verify').resolves({
    sub: 'sub-1',
    email: 'in-token@affine.pro',
  } as JWTPayload);

  const result = await verifier.verifyAndExtractEmail('tok');

  t.is(result.email, 'in-token@affine.pro');
  // only the discovery fetch happened; userinfo was never queried.
  t.false(fetchStub.calledWith(USERINFO as any));
});

test('email absent on token → userinfo fallback resolves it', async t => {
  const { verifier, fetchStub } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verify').resolves({
    sub: 'sub-1',
    // no email — Zitadel-style access token
  } as JWTPayload);
  fetchStub
    .withArgs(USERINFO as any)
    .resolves(jsonResponse({ sub: 'sub-1', email: 'from-userinfo@affine.pro' }));

  const result = await verifier.verifyAndExtractEmail('tok');

  t.is(result.email, 'from-userinfo@affine.pro');
  const call = fetchStub
    .getCalls()
    .find(c => c.args[0] === USERINFO);
  t.truthy(call);
  // bearer is the verified access token; never logged.
  t.is(
    (call?.args[1]?.headers as Record<string, string>).Authorization,
    'Bearer tok'
  );
});

test('email absent on token AND userinfo → email undefined (rejected upstream)', async t => {
  const { verifier, fetchStub } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verify').resolves({ sub: 'sub-1' } as JWTPayload);
  fetchStub
    .withArgs(USERINFO as any)
    .resolves(jsonResponse({ sub: 'sub-1' }));

  const result = await verifier.verifyAndExtractEmail('tok');
  t.is(result.email, undefined);
});

test('userinfo non-200 → InvalidAuthState', async t => {
  const { verifier, fetchStub } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verify').resolves({ sub: 'sub-1' } as JWTPayload);
  fetchStub
    .withArgs(USERINFO as any)
    .resolves(jsonResponse({ error: 'invalid_token' }, false, 401));

  await t.throwsAsync(verifier.verifyAndExtractEmail('tok'));
});

test('userinfo network error → InvalidAuthState', async t => {
  const { verifier, fetchStub } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verify').resolves({ sub: 'sub-1' } as JWTPayload);
  fetchStub.withArgs(USERINFO as any).rejects(new Error('ECONNREFUSED'));

  await t.throwsAsync(verifier.verifyAndExtractEmail('tok'));
});

test('configured claim_email name is honored on token fast path', async t => {
  const { verifier } = await configuredVerifier(
    makeConfig({ claim_email: 'mail' })
  );
  Sinon.stub(verifier, 'verify').resolves({
    sub: 'sub-1',
    mail: 'custom-claim@affine.pro',
  } as unknown as JWTPayload);

  const result = await verifier.verifyAndExtractEmail('tok');
  t.is(result.email, 'custom-claim@affine.pro');
});

test('configured claim_email name is honored in userinfo fallback', async t => {
  const { verifier, fetchStub } = await configuredVerifier(
    makeConfig({ claim_email: 'mail' })
  );
  Sinon.stub(verifier, 'verify').resolves({ sub: 'sub-1' } as JWTPayload);
  fetchStub
    .withArgs(USERINFO as any)
    .resolves(jsonResponse({ sub: 'sub-1', mail: 'custom-ui@affine.pro' }));

  const result = await verifier.verifyAndExtractEmail('tok');
  t.is(result.email, 'custom-ui@affine.pro');
});

test('no userinfo_endpoint in discovery → email-absent yields undefined (no throw)', async t => {
  const { verifier } = await configuredVerifier(makeConfig(), {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/oidc/jwks`,
    // userinfo_endpoint omitted
  });
  Sinon.stub(verifier, 'verify').resolves({ sub: 'sub-1' } as JWTPayload);

  const result = await verifier.verifyAndExtractEmail('tok');
  t.is(result.email, undefined);
});
