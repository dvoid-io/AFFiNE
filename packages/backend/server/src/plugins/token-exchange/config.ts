import { z } from 'zod';

import { defineModuleConfig } from '../../base';

export interface TokenExchangeConfig {
  /**
   * Shared secret a trusted reverse-proxy / BFF / gateway presents (via the
   * `x-affine-trusted-proxy-secret` header) to prove it is the sanctioned
   * caller of the token-exchange endpoint.
   *
   * A verified user token alone is not enough to mint a session: the endpoint
   * is publicly routable, so a leaked user access token would otherwise be a
   * full account takeover. The shared secret is the second factor that binds
   * minting to the deployment's own trusted front door.
   *
   * Empty disables the endpoint entirely (it responds `404`, byte-identical to
   * a deployment that never shipped the feature).
   */
  trustedProxySecret: string;
  /**
   * Expected `aud` (audience) of the inbound OIDC access token. Most providers
   * audience access tokens to the resource/API they are scoped for, which is
   * distinct from the login `clientId`, so this is a dedicated key.
   *
   * Empty skips audience verification — insecure, intended only for local
   * development. Set it in production.
   */
  audience: string;
}

declare global {
  interface AppConfigSchema {
    tokenExchange: TokenExchangeConfig;
  }
}

defineModuleConfig('tokenExchange', {
  trustedProxySecret: {
    desc: 'Shared secret a trusted reverse-proxy/gateway presents (via the `x-affine-trusted-proxy-secret` header) to reach the OAuth token-exchange endpoint. Empty disables the endpoint.',
    default: '',
    env: 'AFFINE_TOKEN_EXCHANGE_TRUSTED_PROXY_SECRET',
    shape: z.string(),
  },
  audience: {
    desc: 'Expected audience (`aud`) of inbound OIDC access tokens at the token-exchange endpoint. Empty skips audience verification.',
    default: '',
    env: 'AFFINE_TOKEN_EXCHANGE_AUDIENCE',
    shape: z.string(),
  },
});
