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
});

const OIDCEmailSchema = z.string().email();

/**
 * The verified subject's identity, resolved from a verified OIDC id_token:
 * the `email` (canonical join key) plus an optional display `name`.
 */
export interface ResolvedIdentity {
  email: string;
  name: string | undefined;
}

/**
 * Verifies inbound OIDC tokens for the RFC 8693 token-exchange flow against the
 * configured provider's JWKS, reusing the *same* `jose` primitives the OAuth
 * OIDC login flow uses (`createRemoteJWKSet` + `jwtVerify`) and the *same*
 * issuer config (`oauth.providers.oidc.issuer`). It is therefore IdP-neutral —
 * it works with any standards-compliant OIDC provider (Keycloak, Auth0, Okta,
 * Zitadel, …) purely from the configured issuer + audience + discovery doc.
 *
 * Two tokens are involved:
 *   - the **access token** (RFC 8693 `subject_token`) — audience-checked against
 *     `tokenExchange.audience`; it authorizes the exchange and names the subject.
 *   - the **id_token** (RFC 8693 `actor_token`) — the cryptographically-signed
 *     identity assertion that carries `email`. Providers like Zitadel do NOT
 *     place `email` on the access token, so we read it from the id_token.
 *
 * Why the id_token and NOT the OIDC userinfo endpoint: userinfo is an
 * out-of-band HTTP hop on the hot path — a flaky extra dependency that, when it
 * failed, masked itself as a generic auth-state error. The id_token is a
 * first-class signed assertion of exactly the claim we need, so we read `email`
 * straight from it: no network hop, no fallback, fail-fast on any problem.
 */
@Injectable()
export class OidcAccessTokenVerifier implements OnModuleDestroy {
  private readonly logger = new Logger(OidcAccessTokenVerifier.name);

  #jwks: JWTVerifyGetKey | null = null;
  #issuer: string | null = null;
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
      return;
    }

    // Resolve `jwks_uri` from the OIDC discovery document — the same source
    // `OIDCProvider` reads — instead of hardcoding a provider-specific path.
    // This keeps the verifier IdP-agnostic and consistent with the login flow.
    const res = await fetch(`${issuer}/.well-known/openid-configuration`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      this.logger.error(`Invalid OIDC issuer ${issuer}`);
      this.#jwks = null;
      this.#issuer = null;
      return;
    }
    const discovery = OIDCDiscoverySchema.parse(await res.json());

    this.#issuer = discovery.issuer.replace(/\/+$/, '');
    this.#jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));

    const audience = this.config.tokenExchange.audience?.trim();
    this.#audience = audience ? audience : undefined;
    if (!this.#audience) {
      this.logger.warn(
        'tokenExchange.audience is unset — inbound access tokens will not be audience-checked'
      );
    }
  }

  /**
   * Verify a bearer access token (the RFC 8693 `subject_token`) and return its
   * claims. Audience-checked against `tokenExchange.audience`. Throws
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
   * Verify an OIDC **id_token** (the RFC 8693 `actor_token`) against the same
   * issuer + JWKS as the access token, and return its claims.
   *
   * Audience is intentionally NOT checked: an id_token's `aud` is the OIDC
   * client_id, not the resource audience the access token carries. The trust
   * that matters is established by the caller via the `sub`-binding in
   * `verifyIdTokenEmail`. Throws `InvalidAuthState` on crypto-verify failure.
   *
   * Exposed (not private) as the testable seam — mirrors `verify`.
   */
  async verifyIdToken(idToken: string): Promise<JWTPayload> {
    if (!this.#jwks || !this.#issuer) {
      this.logger.error('OIDC access-token verifier is not configured');
      throw new InvalidAuthState();
    }

    try {
      const { payload } = await jwtVerify(idToken, this.#jwks, {
        issuer: this.#issuer,
      });
      return payload;
    } catch (err) {
      this.logger.warn('Failed to verify inbound OIDC id_token', err);
      throw new InvalidAuthState();
    }
  }

  /**
   * Verify the id_token and resolve the verified subject's `email` (+ display
   * name), bound to the already-verified access token's subject.
   *
   * `expectedSub` is the access token's `sub`. The id_token's `sub` MUST equal
   * it — this proves the id_token names the *same* user the access token
   * authorizes, so a caller cannot pair user A's access token with user B's
   * id_token.
   *
   * Fails fast with `InvalidAuthState` — with a precise log per cause — on:
   * id_token crypto-verify failure (`verifyIdToken`), `sub` mismatch, or an
   * id_token carrying no valid email claim. No degrade, no fallback.
   */
  async verifyIdTokenEmail(
    idToken: string,
    expectedSub: string
  ): Promise<ResolvedIdentity> {
    const payload = await this.verifyIdToken(idToken);

    if (!payload.sub || payload.sub !== expectedSub) {
      this.logger.warn(
        'id_token subject does not match the access token subject; refusing to cross identities'
      );
      throw new InvalidAuthState();
    }

    const email = this.readEmail(payload, this.emailClaimName());
    if (!email) {
      this.logger.warn(
        'Inbound id_token has no valid email claim; cannot resolve user'
      );
      throw new InvalidAuthState();
    }

    return {
      email,
      name: typeof payload.name === 'string' ? payload.name : undefined,
    };
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
   * Read a syntactically valid email from a claims record under the configured
   * claim name. Returns `undefined` if absent or not an email.
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
}
