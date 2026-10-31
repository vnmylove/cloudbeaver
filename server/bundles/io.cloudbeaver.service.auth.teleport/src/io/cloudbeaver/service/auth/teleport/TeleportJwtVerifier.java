/*
 * DBeaver - Universal Database Manager
 * Copyright (C) 2010-2026 DBeaver Corp and others
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudbeaver.service.auth.teleport;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Verifies a Teleport application-access JWT.
 * The accepted algorithms are fixed here; the algorithm named in the token header is only used to
 * select between them and must match the algorithm of the key it is verified with.
 */
public class TeleportJwtVerifier {
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of(
        TeleportConstants.ALG_RS256,
        TeleportConstants.ALG_ES256
    );
    private static final Gson GSON = new Gson();
    private static final Type CLAIMS_TYPE = new TypeToken<Map<String, Object>>() {
    }.getType();

    @NotNull
    private final JwksProvider jwksProvider;
    @NotNull
    private final String issuer;
    @NotNull
    private final String audience;
    private final long clockSkewSeconds;

    public TeleportJwtVerifier(
        @NotNull JwksProvider jwksProvider,
        @NotNull String issuer,
        @NotNull String audience,
        long clockSkewSeconds
    ) {
        this.jwksProvider = jwksProvider;
        this.issuer = issuer;
        this.audience = audience;
        this.clockSkewSeconds = clockSkewSeconds;
    }

    public TeleportJwtVerifier(@NotNull JwksProvider jwksProvider, @NotNull TeleportSettings settings) {
        this(jwksProvider, settings.getIssuer(), settings.getAudience(), settings.getClockSkewSeconds());
    }

    @NotNull
    public Map<String, Object> verify(@NotNull String jwt) throws TeleportJwtException {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new TeleportJwtException("JWT must have three segments");
        }
        Map<String, Object> header = decodeJson(parts[0], "header");
        String algorithm = stringClaim(header, "alg");
        if (!ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw new TeleportJwtException("Rejected JWT algorithm '" + algorithm + "'");
        }

        String kid = header.get("kid") instanceof String value ? value : "";
        JwkEntry key;
        try {
            key = jwksProvider.getKey(kid);
        } catch (TeleportJwtException e) {
            throw e;
        } catch (Exception e) {
            throw new TeleportJwtException("Failed to resolve signing key", e);
        }
        if (!algorithm.equals(key.alg())) {
            throw new TeleportJwtException(
                "alg mismatch: header=" + algorithm + " jwk=" + key.alg());
        }

        byte[] signatureBytes = decode(parts[2], "signature");
        if (TeleportConstants.ALG_ES256.equals(algorithm)) {
            try {
                signatureBytes = EcSignatureConverter.convertJwsEcSignatureToDer(signatureBytes);
            } catch (IllegalArgumentException e) {
                throw new TeleportJwtException("Invalid ES256 signature", e);
            }
        }
        if (!verifySignature(algorithm, key, parts[0] + "." + parts[1], signatureBytes)) {
            throw new TeleportJwtException("JWT signature verification failed");
        }

        Map<String, Object> claims = decodeJson(parts[1], "payload");
        validateClaims(claims);
        return claims;
    }

    private boolean verifySignature(
        @NotNull String algorithm,
        @NotNull JwkEntry key,
        @NotNull String signingInput,
        @NotNull byte[] signatureBytes
    ) throws TeleportJwtException {
        String jcaAlgorithm = TeleportConstants.ALG_ES256.equals(algorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            signature.initVerify(key.publicKey());
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            throw new TeleportJwtException("JWT signature verification failed", e);
        }
    }

    private void validateClaims(@NotNull Map<String, Object> claims) throws TeleportJwtException {
        if (!issuer.equals(stringClaim(claims, "iss"))) {
            throw new TeleportJwtException("JWT issuer does not match");
        }
        if (!audienceMatches(claims.get("aud"))) {
            throw new TeleportJwtException("JWT audience does not match");
        }
        long now = Instant.now().getEpochSecond();
        Long expiration = numberClaim(claims, "exp");
        if (expiration == null || expiration + clockSkewSeconds <= now) {
            throw new TeleportJwtException("JWT is expired");
        }
        Long notBefore = numberClaim(claims, "nbf");
        if (notBefore != null && notBefore - clockSkewSeconds > now) {
            throw new TeleportJwtException("JWT is not valid yet");
        }
    }

    private boolean audienceMatches(@Nullable Object audienceClaim) {
        if (audienceClaim instanceof String value) {
            return audience.equals(value);
        }
        if (audienceClaim instanceof Collection<?> values) {
            for (Object value : values) {
                if (audience.equals(String.valueOf(value))) {
                    return true;
                }
            }
        }
        return false;
    }

    @NotNull
    private Map<String, Object> decodeJson(@NotNull String segment, @NotNull String name) throws TeleportJwtException {
        try {
            String json = new String(decode(segment, name), StandardCharsets.UTF_8);
            Map<String, Object> parsed = GSON.fromJson(json, CLAIMS_TYPE);
            if (parsed == null) {
                throw new TeleportJwtException("JWT " + name + " is empty");
            }
            return parsed;
        } catch (TeleportJwtException e) {
            throw e;
        } catch (Exception e) {
            throw new TeleportJwtException("JWT " + name + " is not valid JSON", e);
        }
    }

    @NotNull
    private static byte[] decode(@NotNull String segment, @NotNull String name) throws TeleportJwtException {
        try {
            return Base64.getUrlDecoder().decode(segment);
        } catch (IllegalArgumentException e) {
            throw new TeleportJwtException("JWT " + name + " is not valid base64url", e);
        }
    }

    @Nullable
    private static String stringClaim(@NotNull Map<String, Object> claims, @NotNull String name) {
        Object value = claims.get(name);
        return value instanceof String text ? text : null;
    }

    @Nullable
    private static Long numberClaim(@NotNull Map<String, Object> claims, @NotNull String name) {
        Object value = claims.get(name);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return null;
    }
}
