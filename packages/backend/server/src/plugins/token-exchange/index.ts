import './config';

import { Module } from '@nestjs/common';

import { AuthModule } from '../../core/auth';
import { UserModule } from '../../core/user';
import { TokenExchangeController } from './controller';
import { TokenExchangeService } from './service';
import { OidcAccessTokenVerifier } from './verifier';

/**
 * Token-exchange plugin: an RFC 8693 OAuth 2.0 Token Exchange endpoint that
 * accepts a verified external OIDC access token plus a trusted-proxy shared
 * secret, and mints an AFFiNE session for the resolved user. Lives in its own
 * plugin module to keep the upstream-merge conflict surface minimal (the
 * alternative is co-locating in the oauth plugin).
 *
 * Registers its own `tokenExchange` config (trusted-proxy secret + audience)
 * via the side-effect `import './config'`, mirroring the oauth plugin. Depends
 * on AuthModule (for SessionIssuer) and UserModule. The OIDC *issuer* it reads
 * is owned by the oauth plugin's `defineModuleConfig('oauth')`, loaded globally
 * at boot, so we don't need to import OAuthModule.
 *
 * The endpoint is fully inert (responds `404`) until both the trusted-proxy
 * secret and an OIDC provider issuer are configured — existing deployments are
 * unaffected.
 */
@Module({
  imports: [AuthModule, UserModule],
  providers: [OidcAccessTokenVerifier, TokenExchangeService],
  controllers: [TokenExchangeController],
})
export class TokenExchangeModule {}
