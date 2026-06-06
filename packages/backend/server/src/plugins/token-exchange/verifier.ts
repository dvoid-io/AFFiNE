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
}
