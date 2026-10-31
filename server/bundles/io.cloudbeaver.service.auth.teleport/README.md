# Teleport JWT authentication

CloudBeaver can sign a user in from the JWT that [Teleport Application Access](https://goteleport.com/docs/enroll-resources/application-access/)
adds to every proxied request. The token arrives in the `Teleport-Jwt-Assertion` header. CloudBeaver checks the
signature, issuer, audience and lifetime, creates the user on the first login, and maps the token's roles to
CloudBeaver teams.

No browser change is required. Once the provider is enabled, opening CloudBeaver through Teleport signs the user in.

## What CloudBeaver checks

The signature is checked against the keys Teleport publishes at `https://<proxy>/.well-known/jwks.json`.
Both algorithms Teleport uses are accepted:

| Teleport setting | Token algorithm | Key type |
| --- | --- | --- |
| `signature_algorithm_suite: balanced-v1` (default since Teleport 15) | ES256 | EC P-256 |
| `signature_algorithm_suite: legacy` | RS256 | RSA |

The algorithm is chosen from the published key, not from the token header. A token whose header names a different
algorithm, or names `none` or an HMAC algorithm, is rejected. Check which algorithm a cluster uses:

```sh
curl -ks https://<proxy>/.well-known/jwks.json | jq '.keys[0].alg'
```

Keys are cached for `jwks-cache-ttl-seconds` (default one hour). A token signed by a key that is not cached triggers
one refresh, so a key rotation is picked up immediately. If the JWKS endpoint cannot be reached, nobody is signed in.

The token is checked once, when the CloudBeaver session opens. After that the CloudBeaver session lives on its own
until `expireSessionAfterPeriod`. Signing the user out of Teleport does not end the CloudBeaver session.

## Teams and roles

Teleport roles and CloudBeaver concepts are three different things:

| Name | What it is |
| --- | --- |
| `roles` | The claim Teleport puts in the JWT. This is the default value of the `teams-claim` setting. |
| `teams-claim` | The CloudBeaver setting that names which JWT claim is read. Each value is matched to a CloudBeaver team. |
| Auth role | The CloudBeaver permission level (`admin`, `user`, ...). It comes from `auth-role-claim` and has nothing to do with team membership. |

A role is only applied when a CloudBeaver team already carries it. Create the team first, then set its
`teleport.role-name` metadata to the Teleport role name. Roles with no matching team are ignored, so a token can
never create a team or fail the login. A user whose token matches nothing gets only the default user team.

`team-filter-prefix` keeps only values that start with the prefix. `team-strip-prefix` removes a prefix before the
value is compared with `teleport.role-name`.

## Settings

| Setting | Required | Default | Meaning |
| --- | --- | --- | --- |
| `jwks-url` | yes | | Teleport JWKS endpoint |
| `issuer` | yes | | Expected `iss`. This is the Teleport cluster name |
| `audience` | yes | | Expected `aud`. Copy it exactly from a real token |
| `header-name` | | `Teleport-Jwt-Assertion` | Header that carries the token |
| `username-claim` | | `username` | Claim used as the CloudBeaver user id. Falls back to `sub` |
| `display-name-claim` | | `username` | Claim used as the display name |
| `teams-claim` | | `roles` | Claim whose values map to teams |
| `team-filter-prefix` | | | Only values with this prefix are mapped |
| `team-strip-prefix` | | | Prefix removed before matching a team |
| `auth-role-claim` | | | Claim that sets the CloudBeaver auth role |
| `clock-skew-seconds` | | `60` | Allowed clock difference |
| `jwks-cache-ttl-seconds` | | `3600` | How long signing keys are reused |
| `logout-url` | | | Page opened on sign out, for example `https://<proxy>/web/logout` |

`audience` is compared byte for byte. Teleport usually puts the application's public address there, sometimes with a
scheme and sometimes without. Read it from a real token instead of guessing:

```sh
echo '<payload segment>' | base64 -d | jq .aud
```

User names are matched without case sensitivity, so `Alice` and `alice` are the same CloudBeaver user.

## Teleport application

```yaml
app_service:
  enabled: "yes"
  apps:
    - name: cloudbeaver
      uri: http://cloudbeaver:8978
      public_addr: cloudbeaver.example.com
      rewrite:
        headers:
          - "Host: cloudbeaver.example.com"
```

Enable the `teleport` provider in CloudBeaver and add a configuration with the three required settings. The provider
stays disabled until that configuration exists.

Requests that reach CloudBeaver directly have no Teleport header and are not signed in. Publish CloudBeaver only
through Teleport, or restrict `supportedHosts`, so the login cannot be bypassed.

## Trusting the JWKS endpoint

CloudBeaver downloads the JWKS document over HTTPS and checks the certificate. A cluster with a public certificate
needs nothing extra. A development cluster that signs its own certificate needs that certificate in the JVM trust
store:

```sh
tctl get cert_authority/host/<cluster> --format=json \
  | jq -r '.spec.active_keys.tls[0].cert' | base64 -d > /tmp/teleport-ca.pem
keytool -importcert -alias teleport -file /tmp/teleport-ca.pem \
  -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit -noprompt
```

Verified against Teleport 18.7.6, which signs these tokens with ES256.
