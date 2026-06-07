import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import {
  createRemoteJWKSet,
  type JWTPayload,
  jwtVerify,
  type JWTVerifyGetKey,
} from 'jose';
import { z } from 'zod';

import { Config, InvalidAuthState, OnEvent } from '../../base';
import { OAuthOIDCProviderConfig, OAuthProviderName } from '../oauth/config';

const OIDCDiscoverySchema = z.object({
  issuer: z.string(),
  jwks_uri: z.string().url(),
  // Standard OIDC userinfo endpoint. Optional in the schema so a minimal
  // discovery doc (or a provider that omits it) still configures the verifier;
  // the email-from-userinfo fallback is simply unavailable in that case.
  userinfo_endpoint: z.string().url().optional(),
});

const OIDCEmailSchema = z.string().email();

// Bound the userinfo round-trip so a slow/hung IdP cannot stall token-exchange.
const USERINFO_FETCH_TIMEOUT_MS = 5_000;

/**
 * Result of verifying an inbound access token: the verified JWT claims, plus
 * the resolved `email` of the verified subject. `email` is `undefined` only
 * when it is present in neither the (cryptographically verified) token claims
 * nor the OIDC userinfo response for that subject.
 */
export interface VerifiedAccessToken {
  claims: JWTPayload;
  email: string | undefined;
}

/**
 * Verifies an inbound OIDC access token (a plain JWS) against the configured
 * provider's JWKS, reusing the *same* `jose` primitives the OAuth OIDC login
 * flow uses (`createRemoteJWKSet` + `jwtVerify`) and the *same* issuer config
 * (`oauth.providers.oidc.issuer`). It is therefore IdP-neutral — it works with
 * any standards-compliant OIDC provider (Keycloak, Auth0, Okta, Zitadel, …)
 * purely from the configured issuer + audience + discovery document.
 *
 * Why this is NOT a direct reuse of `OIDCProvider#verifyIdToken`: that method
 * is `private` and bound to the login handshake — it verifies an `id_token`
 * and asserts a one-time `nonce` that only exists during a redirect callback.
 * A server-to-server access token has no nonce and a different `aud`. So we
 * re-implement the verify with the identical library + identical issuer config
 * and resolve `jwks_uri` via the same OIDC discovery document the provider uses.
 *
 * Email resolution: the canonical OIDC join key is `email`, but many providers
 * (e.g. Zitadel) do NOT place `email` on the *access* token — the access token
 * carries only `{aud, iss, exp, sub, client_id, scope, …}`. `email` lives on
 * the id_token / userinfo. So after the token is cryptographically verified,
 * if the claim is absent we fall back to the standard OIDC `userinfo_endpoint`
 * (from the same discovery doc) using the verified access token as the bearer.
 * The userinfo response is trusted ONLY for the email of the already-verified
 * subject — never for identity beyond it.
 */
@Injectable()
export class OidcAccessTokenVerifier implements OnModuleDestroy {
  private readonly logger = new Logger(OidcAccessTokenVerifier.name);

  #jwks: JWTVerifyGetKey | null = null;
  #issuer: string | null = null;
  // Discovered standard OIDC userinfo endpoint, cached alongside the JWKS from
  // the same discovery document. `null` when the provider's discovery doc omits
  // it — the email-from-userinfo fallback is then unavailable.
  #userinfoEndpoint: string | null = null;
  // Expected `aud` of the inbound access token. Providers typically audience
  // access tokens to the resource/API they are scoped for, not to the login
  // `clientId`, so this is sourced from a dedicated config key
  // (`tokenExchange.audience`). Empty => skip audience verification.
  #audience: string | undefined = undefined;

  constructor(private readonly config: Config) {}

  onModuleDestroy() {
    this.#jwks = null;
  }

  @OnEvent('config.init')
  onConfigInit() {
    this.setup().catch(e =>
      this.logger.error('Failed to set up OIDC access-token verifier', e)
    );
  }

  @OnEvent('config.changed')
  onConfigUpdated(event: Events['config.changed']) {
    if ('oauth' in event.updates || 'tokenExchange' in event.updates) {
      this.setup().catch(e =>
        this.logger.error('Failed to set up OIDC access-token verifier', e)
      );
    }
  }

  /**
   * True once an OIDC issuer is configured and its JWKS has been resolved.
   * The controller uses this to keep the endpoint inert (404) until the
   * required OIDC provider config is present.
   */
  get configured() {
    return this.#jwks !== null && this.#issuer !== null;
  }

  private async setup() {
    const oidc = this.config.oauth.providers[
      OAuthProviderName.OIDC
    ] as OAuthOIDCProviderConfig;

    const issuer = oidc?.issuer?.replace(/\/+$/, '');
    if (!issuer) {
      this.#jwks = null;
      this.#issuer = null;
      this.#userinfoEndpoint = null;
      return;
    }

    // Resolve `jwks_uri` (and `userinfo_endpoint`) from the OIDC discovery
    // document — the same source `OIDCProvider` reads — instead of hardcoding a
    // provider-specific path. This keeps the verifier IdP-agnostic and
    // consistent with the login flow.
    const res = await fetch(`${issuer}/.well-known/openid-configuration`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      this.logger.error(`Invalid OIDC issuer ${issuer}`);
      this.#jwks = null;
      this.#issuer = null;
      this.#userinfoEndpoint = null;
      return;
    }
    const discovery = OIDCDiscoverySchema.parse(await res.json());

    this.#issuer = discovery.issuer.replace(/\/+$/, '');
    this.#jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
    this.#userinfoEndpoint = discovery.userinfo_endpoint ?? null;
    if (!this.#userinfoEndpoint) {
      this.logger.warn(
        'OIDC discovery document has no `userinfo_endpoint` — email-from-userinfo fallback is unavailable'
      );
    }

    const audience = this.config.tokenExchange.audience?.trim();
    this.#audience = audience ? audience : undefined;
    if (!this.#audience) {
      this.logger.warn(
        'tokenExchange.audience is unset — inbound access tokens will not be audience-checked'
      );
    }
  }

  /**
   * Verify a bearer access token and return its claims. Throws
   * `InvalidAuthState` on any failure — the same error surface the OIDC login
   * path uses, so callers/guards behave identically.
   */
  async verify(accessToken: string): Promise<JWTPayload> {
    if (!this.#jwks || !this.#issuer) {
      this.logger.error('OIDC access-token verifier is not configured');
      throw new InvalidAuthState();
    }

    try {
      const { payload } = await jwtVerify(accessToken, this.#jwks, {
        issuer: this.#issuer,
        ...(this.#audience ? { audience: this.#audience } : {}),
      });
      return payload;
    } catch (err) {
      this.logger.warn('Failed to verify inbound OIDC access token', err);
      throw new InvalidAuthState();
    }
  }

  /**
   * Verify a bearer access token and resolve the verified subject's `email`.
   *
   * The token is cryptographically verified first (`verify`). The email is then
   * taken from the verified claims using the configured email claim name
   * (`oauth.providers.oidc.args.claim_email`, default `email`). If the access
   * token carries no email — common for providers like Zitadel that scope
   * `email` to the id_token/userinfo, not the access token — we fall back to the
   * discovered OIDC `userinfo_endpoint`, authenticated with the *same verified*
   * access token, and read the email claim from that response.
   *
   * Returns `email: undefined` when neither source yields a valid email; the
   * caller maps that to the existing "no email" rejection. Throws
   * `InvalidAuthState` (the standard surface) if the userinfo call itself fails
   * (network error, timeout, non-200, unparseable body).
   */
  async verifyAndExtractEmail(
    accessToken: string
  ): Promise<VerifiedAccessToken> {
    const claims = await this.verify(accessToken);

    const emailClaim = this.emailClaimName();

    // Fast path: email is present on the verified access token.
    const fromToken = this.readEmail(claims, emailClaim);
    if (fromToken) {
      return { claims, email: fromToken };
    }

    // Fallback: query the standard OIDC userinfo endpoint for the verified
    // subject. Only reached when the access token lacks email.
    const fromUserinfo = await this.fetchEmailFromUserinfo(
      accessToken,
      emailClaim
    );
    return { claims, email: fromUserinfo };
  }

  /**
   * The configured email claim name, honoring the OAuth OIDC plugin's
   * `claim_email` arg (the same key the login flow uses). Defaults to the
   * standard `email` claim.
   */
  private emailClaimName(): string {
    const oidc = this.config.oauth.providers[
      OAuthProviderName.OIDC
    ] as OAuthOIDCProviderConfig;
    const configured = oidc?.args?.claim_email;
    return typeof configured === 'string' && configured.length > 0
      ? configured
      : 'email';
  }

  /**
   * Read a syntactically valid email from a claims/userinfo record under the
   * configured claim name. Returns `undefined` if absent or not an email.
   */
  private readEmail(
    source: Record<string, unknown>,
    claim: string
  ): string | undefined {
    const value = source[claim];
    if (typeof value === 'string' && OIDCEmailSchema.safeParse(value).success) {
      return value;
    }
    return undefined;
  }

  /**
   * Call the discovered OIDC userinfo endpoint with the verified access token
   * and extract the email claim. The access token has already been
   * cryptographically verified by the caller; userinfo is trusted ONLY for the
   * email of that verified subject. Any transport/parse failure surfaces as
   * `InvalidAuthState` — the same failure surface as a bad token. The bearer
   * token is never logged.
   */
  private async fetchEmailFromUserinfo(
    accessToken: string,
    emailClaim: string
  ): Promise<string | undefined> {
    if (!this.#userinfoEndpoint) {
      // No userinfo endpoint to fall back to: treat as "email absent" (the
      // existing no-email rejection), not a transport failure.
      this.logger.warn(
        'Access token has no email claim and no `userinfo_endpoint` is configured; cannot resolve email'
      );
      return undefined;
    }

    let res: Response;
    try {
      res = await fetch(this.#userinfoEndpoint, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        signal: AbortSignal.timeout(USERINFO_FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      this.logger.warn('OIDC userinfo request failed', err);
      throw new InvalidAuthState();
    }

    if (!res.ok) {
      this.logger.warn(
        `OIDC userinfo endpoint returned non-200 status ${res.status}`
      );
      throw new InvalidAuthState();
    }

    let body: unknown;
    try {
      body = await res.json();
    } catch (err) {
      this.logger.warn('Failed to parse OIDC userinfo response', err);
      throw new InvalidAuthState();
    }

    if (typeof body !== 'object' || body === null) {
      this.logger.warn('OIDC userinfo response was not a JSON object');
      throw new InvalidAuthState();
    }

    return this.readEmail(body as Record<string, unknown>, emailClaim);
  }
}
