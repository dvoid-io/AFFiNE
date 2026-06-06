import { Injectable, Logger } from '@nestjs/common';

import {
  Config,
  EventBus,
  InvalidAuthState,
  SignUpForbidden,
} from '../../base';
import type { VerifiedIdentity } from '../../core/auth';
import { validators } from '../../core/utils/validators';
import { Models } from '../../models';
import { OidcAccessTokenVerifier } from './verifier';

declare global {
  interface Events {
    /**
     * Emitted when the token-exchange endpoint mints a session for a user on
     * behalf of a trusted proxy — the "trusted caller acted AS user X"
     * provenance, recorded through AFFiNE's event system.
     */
    'tokenExchange.identityMinted': {
      userId: string;
      tokenSub?: string;
      tokenJti?: string;
    };
  }
}

@Injectable()
export class TokenExchangeService {
  private readonly logger = new Logger(TokenExchangeService.name);

  constructor(
    private readonly verifier: OidcAccessTokenVerifier,
    private readonly models: Models,
    private readonly config: Config,
    private readonly event: EventBus
  ) {}

  /**
   * verify → extract email → resolve/auto-provision → VerifiedIdentity.
   *
   * Headless analog of `OAuthService.verifyCallbackIdentity`:
   *   - login path:  getToken → getUser → getOrCreateUserFromOauth → identity
   *   - this path:   verify(access_token) → email → fulfill → identity
   *
   * Auto-provision is gated on `auth.allowSignupForOauth`, identical to
   * `OAuthService.getOrCreateUserFromOauth` — so an operator who disables OAuth
   * signups also disables provisioning via token-exchange.
   */
  async exchange(accessToken: string): Promise<VerifiedIdentity> {
    const claims = await this.verifier.verify(accessToken);

    // Email is the canonical OIDC join key. A provider only emits `email` on
    // the access token when it is minted with the `email` scope / a claim
    // mapper; if absent, reject rather than guess.
    const email = typeof claims.email === 'string' ? claims.email : undefined;
    if (!email) {
      this.logger.warn(
        'Inbound access token has no `email` claim; cannot resolve user'
      );
      throw new InvalidAuthState();
    }
    validators.assertValidEmail(email);

    const existing = await this.models.user.getUserByEmail(email);
    if (!existing && !this.config.auth.allowSignupForOauth) {
      throw new SignUpForbidden();
    }

    // Resolve existing user by email, or create a registered, email-verified
    // user — the same `models.user.fulfill(...)` call the OAuth signup path
    // makes (`plugins/oauth/service.ts`).
    const user = await this.models.user.fulfill(email, {
      name: typeof claims.name === 'string' ? claims.name : undefined,
    });

    // Audit: "trusted caller acted AS user X" provenance, wired through
    // AFFiNE's event system rather than a bespoke log sink.
    this.event.emit('tokenExchange.identityMinted', {
      userId: user.id,
      tokenSub: typeof claims.sub === 'string' ? claims.sub : undefined,
      tokenJti: typeof claims.jti === 'string' ? claims.jti : undefined,
    });

    return {
      userId: user.id,
      method: 'oauth',
    };
  }
}
