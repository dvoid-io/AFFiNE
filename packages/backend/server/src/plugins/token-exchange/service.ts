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
import { OAuthProviderName } from '../oauth/config';
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
   * Resolve (or first-time provision) the AFFiNE user behind a Zitadel identity.
   *
   * The join key is the **Zitadel `sub`** — stable and immutable — mapped to an
   * AFFiNE user through the same `ConnectedAccount` table the OIDC login uses
   * (`OAuthService.getOrCreateUserFromOauth`). Two shapes:
   *
   *   - **Resolve** (`idToken` absent): the common runtime path. The `sub` from
   *     the verified access token resolves an existing `ConnectedAccount` →
   *     done. No email, no id_token — email changes never affect identity.
   *   - **Provision/link** (`idToken` present): the login path. When the `sub`
   *     is not yet linked, the id_token supplies the email needed to create the
   *     AFFiNE user (or link the `sub` to an existing email-matched user) — the
   *     identical `fulfill(email)` + `createConnectedAccount(sub)` the OIDC
   *     login performs. The id_token is only ever in hand at login, so that is
   *     where provisioning happens; the runtime MCP path never carries it.
   *
   * A `sub` with no `ConnectedAccount` and no id_token means "not provisioned
   * yet" — it fails fast rather than guessing. Auto-provision is gated on
   * `auth.allowSignupForOauth`, identical to the OIDC login.
   */
  async exchange(
    accessToken: string,
    idToken?: string
  ): Promise<VerifiedIdentity> {
    // Verify the access token (RFC 8693 subject_token) — enforces the resource
    // audience and yields the authorized Zitadel subject.
    const claims = await this.verifier.verify(accessToken);
    const sub = typeof claims.sub === 'string' ? claims.sub : undefined;
    if (!sub) {
      this.logger.warn(
        'Inbound access token has no `sub` claim; cannot resolve user'
      );
      throw new InvalidAuthState();
    }

    // Resolve by the stable Zitadel subject via the same ConnectedAccount map
    // the OIDC login uses — no email, no id_token, immutable across email
    // changes.
    const connected = await this.models.user.getConnectedAccount(
      OAuthProviderName.OIDC,
      sub
    );
    if (connected) {
      this.event.emit('tokenExchange.identityMinted', {
        userId: connected.userId,
        tokenSub: sub,
        tokenJti: typeof claims.jti === 'string' ? claims.jti : undefined,
      });
      return { userId: connected.userId, method: 'oauth' };
    }

    // Not linked yet → provision/link. This needs the user's email, which only
    // the id_token carries. Runtime MCP calls omit it (resolution only), so a
    // missing id_token here means the user was never provisioned at login.
    if (!idToken) {
      this.logger.warn(
        'No ConnectedAccount for the Zitadel subject and no id_token to provision; the user must be provisioned at login first'
      );
      throw new InvalidAuthState();
    }

    const { email, name } = await this.verifier.verifyIdTokenEmail(
      idToken,
      sub
    );
    validators.assertValidEmail(email);

    const existing = await this.models.user.getUserByEmail(email);
    if (!existing && !this.config.auth.allowSignupForOauth) {
      throw new SignUpForbidden();
    }

    // `fulfill` upserts by email — links the `sub` to an existing email-created
    // user (backfilling legacy users) or creates a fresh registered user. Then
    // record the `sub` → user mapping so every future call resolves by `sub`.
    const user = await this.models.user.fulfill(email, { name });
    await this.models.user.createConnectedAccount({
      userId: user.id,
      provider: OAuthProviderName.OIDC,
      providerAccountId: sub,
      // The ConnectedAccount row requires an access token; the Zitadel access
      // token is the natural analog of the OIDC login's stored access token.
      accessToken,
    });

    this.event.emit('tokenExchange.identityMinted', {
      userId: user.id,
      tokenSub: sub,
      tokenJti: typeof claims.jti === 'string' ? claims.jti : undefined,
    });

    return { userId: user.id, method: 'oauth' };
  }
}
