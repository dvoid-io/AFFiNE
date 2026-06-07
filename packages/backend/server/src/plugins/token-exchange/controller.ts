import { timingSafeEqual } from 'node:crypto';

import {
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { z } from 'zod';

import {
  AccessDenied,
  BadRequest,
  Config,
  NotFound,
  Throttle,
} from '../../base';
import { Public, SessionIssuer } from '../../core/auth';
import { TokenExchangeService } from './service';
import { OidcAccessTokenVerifier } from './verifier';

const TOKEN_EXCHANGE_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const TRUSTED_PROXY_SECRET_HEADER = 'x-affine-trusted-proxy-secret';

/**
 * RFC 8693 OAuth 2.0 Token Exchange request body (the subset this endpoint
 * accepts). The request is validated with zod, mirroring how
 * `OAuthController` validates its callback body (`plugins/oauth/controller.ts`).
 */
const TokenExchangeBodySchema = z.object({
  grant_type: z.literal(TOKEN_EXCHANGE_GRANT_TYPE),
  subject_token: z.string().min(1),
  subject_token_type: z.literal(ACCESS_TOKEN_TYPE),
});

/**
 * POST /api/auth/token-exchange — RFC 8693 OAuth 2.0 Token Exchange.
 *
 * Converts a verified external OIDC access token into an AFFiNE session. This
 * is an opt-in capability: it is fully inert (responds `404`) unless BOTH a
 * trusted-proxy secret (`tokenExchange.trustedProxySecret`) and an OIDC
 * provider issuer (`oauth.providers.oidc.issuer`) are configured. Existing
 * deployments that configure neither see byte-identical behavior.
 *
 * Inbound (RFC 8693, `application/x-www-form-urlencoded` or JSON):
 *   - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
 *   - `subject_token=<external OIDC access token>` — the user's verified token.
 *   - `subject_token_type=urn:ietf:params:oauth:token-type:access_token`
 *   - header `x-affine-trusted-proxy-secret: <secret>` — proof the caller is
 *     the deployment's sanctioned reverse-proxy/BFF, not an arbitrary client.
 *
 * Trust boundary: verified user token AND constant-time trusted-proxy-secret
 * match. The endpoint is publicly routable, so a leaked user token alone must
 * not mint a session — the shared secret binds minting to the trusted front
 * door. The email is taken from verified token claims only, never a raw header.
 *
 * Outbound (RFC 8693 token-exchange response shape, plus a session cookie):
 *   - `access_token` — the AFFiNE session id (set as the `affine_session`
 *     cookie on the response; the value is the server-to-server replay handle).
 *   - `issued_token_type=urn:ietf:params:oauth:token-type:access_token`
 *   - `token_type=Bearer`
 */
@Throttle('strict')
@Controller('/api/auth')
export class TokenExchangeController {
  constructor(
    private readonly config: Config,
    private readonly sessionIssuer: SessionIssuer,
    private readonly tokenExchange: TokenExchangeService,
    private readonly verifier: OidcAccessTokenVerifier
  ) {}

  @Public()
  @Post('/token-exchange')
  @HttpCode(HttpStatus.OK)
  async exchange(
    @Req() req: Request,
    @Res() res: Response,
    @Body() body?: unknown,
    @Headers(TRUSTED_PROXY_SECRET_HEADER) trustedProxySecret?: string
  ) {
    // Inert when unconfigured: if the operator has not opted in (no trusted
    // proxy secret) or the OIDC provider is not set up (no issuer/JWKS), the
    // endpoint does not exist as far as any caller can tell.
    if (!this.config.tokenExchange.trustedProxySecret || !this.verifier.configured) {
      throw new NotFound();
    }

    if (!this.trustedProxySecretMatches(trustedProxySecret)) {
      throw new AccessDenied('Invalid trusted-proxy credentials');
    }

    const input = TokenExchangeBodySchema.safeParse(body);
    if (!input.success) {
      throw new BadRequest('Malformed RFC 8693 token-exchange request');
    }

    const identity = await this.tokenExchange.exchange(input.data.subject_token);

    // Canonical session mint — the same call `OAuthController.callback` makes.
    // Sets the `affine_session` + csrf cookies on `res` and returns the handle.
    const { sessionId } = await this.sessionIssuer.issue(req, res, identity);

    // RFC 8693 §2.2.1 response shape. The issued "access token" is the AFFiNE
    // session id; a server-to-server caller replays it as
    // `Cookie: affine_session=<access_token>`.
    res.send({
      access_token: sessionId,
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
    });
  }

  /**
   * Constant-time comparison of the presented trusted-proxy secret against
   * config. An unset config secret denies all requests (fail-closed); but the
   * unset case is already handled by the inert 404 above, so reaching here
   * implies a configured secret.
   */
  private trustedProxySecretMatches(presented?: string): boolean {
    const expected = this.config.tokenExchange.trustedProxySecret;
    if (!expected || !presented) {
      return false;
    }
    const a = Buffer.from(presented);
    const b = Buffer.from(expected);
    if (a.length !== b.length) {
      return false;
    }
    return timingSafeEqual(a, b);
  }
}
