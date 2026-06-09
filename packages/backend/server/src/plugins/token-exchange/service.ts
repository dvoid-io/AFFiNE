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
   * verify → bind id_token → extract email → resolve/auto-provision → identity.
   *
   * Headless analog of `OAuthService.verifyCallbackIdentity`:
   *   - login path:  getToken → getUser → getOrCreateUserFromOauth → identity
   *   - this path:   verify(access_token) → email(id_token) → fulfill → identity
   *
   * Auto-provision is gated on `auth.allowSignupForOauth`, identical to
   * `OAuthService.getOrCreateUserFromOauth` — so an operator who disables OAuth
   * signups also disables provisioning via token-exchange.
   */
  async exchange(
    accessToken: string,
    idToken: string
  ): Promise<VerifiedIdentity> {
    // Verify the access token (RFC 8693 subject_token) — enforces the resource
    // audience and yields the authorized subject. The access token does not
    // carry email (Zitadel-style); that comes from the id_token next.
    const claims = await this.verifier.verify(accessToken);
    const sub = typeof claims.sub === 'string' ? claims.sub : undefined;
    if (!sub) {
      this.logger.warn(
        'Inbound access token has no `sub` claim; cannot resolve user'
      );
      throw new InvalidAuthState();
    }

    // Resolve email (+ name) from the id_token (RFC 8693 actor_token), bound to
    // the same subject. No userinfo hop, no fallback — `verifyIdTokenEmail`
    // fails fast with a precise cause if the id_token is bad, mismatched, or
    // carries no email.
    const { email, name } = await this.verifier.verifyIdTokenEmail(
      idToken,
      sub
    );
    validators.assertValidEmail(email);

    const existing = await this.models.user.getUserByEmail(email);
    if (!existing && !this.config.auth.allowSignupForOauth) {
      throw new SignUpForbidden();
    }

    // Resolve existing user by email, or create a registered, email-verified
    // user — the same `models.user.fulfill(...)` call the OAuth signup path
    // makes (`plugins/oauth/service.ts`). The display name comes from the
    // id_token (the access token carries no profile claims).
    const user = await this.models.user.fulfill(email, { name });

    // Audit: "trusted caller acted AS user X" provenance, wired through
    // AFFiNE's event system rather than a bespoke log sink.
    this.event.emit('tokenExchange.identityMinted', {
      userId: user.id,
      tokenSub: sub,
      tokenJti: typeof claims.jti === 'string' ? claims.jti : undefined,
    });

    return {
      userId: user.id,
      method: 'oauth',
    };
  }
}
