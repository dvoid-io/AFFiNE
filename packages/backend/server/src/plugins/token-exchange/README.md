# Token Exchange (RFC 8693)

An opt-in auth mode that converts a verified external **OIDC access token** into
an AFFiNE session, following the [RFC 8693 OAuth 2.0 Token Exchange][rfc8693]
request/response shape.

It is the headless, server-to-server counterpart to the interactive OIDC login
flow in the [`oauth`](../oauth) plugin: instead of a browser redirect handshake,
a trusted backend presents a user's already-issued OIDC access token and
receives an AFFiNE session in return.

## Use case

A reverse proxy, BFF (backend-for-frontend), or API gateway sits in front of
AFFiNE and has already authenticated the user against your OIDC provider
(Keycloak, Auth0, Okta, Zitadel, Entra ID, …). Rather than re-running the OAuth
redirect dance for AFFiNE, the gateway exchanges the user's OIDC access token
for an AFFiNE session and proxies subsequent requests with the session cookie.

This is also the building block for agent / automation flows where a trusted
service acts **as** a user it has already authenticated.

## Backward compatibility — inert when unconfigured

The endpoint is **fully inert** unless you opt in. It responds `404 Not Found`
— byte-identical to a build that never shipped this plugin — until **both** of
these are configured:

1. `tokenExchange.trustedProxySecret` (env `AFFINE_TOKEN_EXCHANGE_TRUSTED_PROXY_SECRET`)
2. An OIDC provider issuer (`oauth.providers.oidc.issuer`), whose JWKS the
   verifier has successfully resolved via OIDC discovery.

Existing deployments that configure neither are unaffected.

## Configuration

| Config key                        | Env var                                       | Required | Description                                                                                                   |
| --------------------------------- | --------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| `tokenExchange.trustedProxySecret`| `AFFINE_TOKEN_EXCHANGE_TRUSTED_PROXY_SECRET`  | yes      | Shared secret the trusted proxy presents. Empty disables (404) the endpoint.                                 |
| `tokenExchange.audience`          | `AFFINE_TOKEN_EXCHANGE_AUDIENCE`              | prod     | Expected `aud` of inbound access tokens. Empty skips audience checking (dev only).                           |
| `oauth.providers.oidc.issuer`     | _(runtime config / `config.json`)_            | yes      | OIDC issuer URL. Reused from the `oauth` plugin; its `/.well-known/openid-configuration` supplies the JWKS.  |

Auto-provisioning of unknown users honors `auth.allowSignupForOauth`, identical
to the interactive OAuth login path — disabling OAuth signups also disables
provisioning here.

## Security model

The endpoint mints sessions, so its trust boundary is **two independent
factors**:

1. **A verified OIDC access token** — signature, `iss`, and `aud` are checked
   against the provider's JWKS (the same `jose` primitives the OIDC login flow
   uses). The user's email is taken from verified token claims only — never from
   a request header.
2. **A trusted-proxy shared secret** — compared in constant time
   (`crypto.timingSafeEqual`), never logged, and fail-closed when unset.

**Why a verified token alone is not enough:** the endpoint is publicly routable.
A user's OIDC access token can leak (logs, referrers, a compromised client).
Without the second factor, a leaked token at a public endpoint would be a full
account takeover. The shared secret binds session minting to the deployment's
own trusted front door, so a leaked token is useless without also compromising
the gateway.

## Request / response (RFC 8693)

```http
POST /api/auth/token-exchange HTTP/1.1
Host: affine.example.com
Content-Type: application/json
x-affine-trusted-proxy-secret: <AFFINE_TOKEN_EXCHANGE_TRUSTED_PROXY_SECRET>

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<the user's OIDC access token>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

```http
HTTP/1.1 200 OK
Set-Cookie: affine_session=<session-id>; HttpOnly; ...

{
  "access_token": "<session-id>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer"
}
```

The issued `access_token` **is** the value of the `affine_session` cookie. A
server-to-server caller replays it as `Cookie: affine_session=<access_token>`;
a browser-fronting proxy can forward the `Set-Cookie` directly.

### Errors

| Condition                                              | Status |
| ------------------------------------------------------ | ------ |
| Plugin not configured (secret and/or OIDC issuer)      | `404`  |
| Missing / wrong trusted-proxy secret                   | `403`  |
| Malformed RFC 8693 body                                | `400`  |
| Invalid / expired token, wrong `iss`/`aud`, no `email` | `400`  |
| Unknown user + `auth.allowSignupForOauth = false`      | `403`  |

[rfc8693]: https://datatracker.ietf.org/doc/html/rfc8693
