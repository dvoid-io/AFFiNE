import test from 'ava';
import type { JWTPayload } from 'jose';
import Sinon from 'sinon';

import type { Config } from '../../../base';
import { OidcAccessTokenVerifier } from '../verifier';

// Unit-test the verifier's id_token email resolution in isolation. The
// cryptographic verify of the id_token (`verifyIdToken`) is stubbed per-test so
// no JWKS/network is needed; the only network exercised is the OIDC discovery
// doc during setup, via a stubbed `global.fetch`. Email resolution reads the
// id_token claims directly — there is no userinfo HTTP hop.

const ISSUER = 'https://issuer.example.com';

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
 * `setup()` resolves the issuer + JWKS, then run setup.
 */
async function configuredVerifier(
  config: Config,
  discovery: Record<string, unknown> = {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/oidc/jwks`,
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

test('id_token with matching sub + email resolves identity', async t => {
  const { verifier } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verifyIdToken').resolves({
    sub: 'sub-1',
    email: 'agent@affine.pro',
    name: 'Agent User',
  } as JWTPayload);

  const result = await verifier.verifyIdTokenEmail('id.tok', 'sub-1');

  t.is(result.email, 'agent@affine.pro');
  t.is(result.name, 'Agent User');
});

test('id_token sub mismatch → InvalidAuthState (no identity crossing)', async t => {
  const { verifier } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verifyIdToken').resolves({
    sub: 'someone-else',
    email: 'evil@affine.pro',
  } as JWTPayload);

  await t.throwsAsync(verifier.verifyIdTokenEmail('id.tok', 'sub-1'));
});

test('id_token without a valid email claim → InvalidAuthState', async t => {
  const { verifier } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verifyIdToken').resolves({
    sub: 'sub-1',
    // no email
  } as JWTPayload);

  await t.throwsAsync(verifier.verifyIdTokenEmail('id.tok', 'sub-1'));
});

test('id_token with non-email value under the claim → InvalidAuthState', async t => {
  const { verifier } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verifyIdToken').resolves({
    sub: 'sub-1',
    email: 'not-an-email',
  } as unknown as JWTPayload);

  await t.throwsAsync(verifier.verifyIdTokenEmail('id.tok', 'sub-1'));
});

test('configured claim_email name is honored', async t => {
  const { verifier } = await configuredVerifier(
    makeConfig({ claim_email: 'mail' })
  );
  Sinon.stub(verifier, 'verifyIdToken').resolves({
    sub: 'sub-1',
    mail: 'custom-claim@affine.pro',
  } as unknown as JWTPayload);

  const result = await verifier.verifyIdTokenEmail('id.tok', 'sub-1');
  t.is(result.email, 'custom-claim@affine.pro');
});

test('id_token missing name → name is undefined (still resolves)', async t => {
  const { verifier } = await configuredVerifier(makeConfig());
  Sinon.stub(verifier, 'verifyIdToken').resolves({
    sub: 'sub-1',
    email: 'noname@affine.pro',
  } as JWTPayload);

  const result = await verifier.verifyIdTokenEmail('id.tok', 'sub-1');
  t.is(result.email, 'noname@affine.pro');
  t.is(result.name, undefined);
});

test('verifyIdToken throws InvalidAuthState when verifier is unconfigured', async t => {
  // No discovery → setup leaves jwks/issuer null.
  const fetchStub = Sinon.stub(global, 'fetch');
  fetchStub
    .withArgs(Sinon.match(/well-known\/openid-configuration/))
    .resolves(jsonResponse({}, false, 500));
  const verifier = new OidcAccessTokenVerifier(makeConfig());
  await (verifier as unknown as { setup: () => Promise<void> }).setup();

  await t.throwsAsync(verifier.verifyIdToken('id.tok'));
  t.false(verifier.configured);
});
