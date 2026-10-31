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
package io.cloudbeaver.service.teleport.auth;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.jkiss.code.NotNull;
import org.jkiss.code.Nullable;
import org.jkiss.dbeaver.Log;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.AlgorithmParameters;
import java.util.function.Supplier;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Fetches a JWKS document and caches the parsed keys until the configured TTL expires.
 * A missing kid triggers one forced refresh so a key rotation is picked up without waiting for the TTL.
 */
public class TeleportJwksCache implements JwksProvider {
    private static final Log log = Log.getLog(TeleportJwksCache.class);

    private static final ECParameterSpec P256_PARAMS = loadP256Params();

    @NotNull
    private final String jwksUrl;
    private final long ttlMillis;
    @NotNull
    private final Supplier<String> documentSource;

    // Only refreshing threads take this lock; readers go through the volatile fields below and never block on it.
    private final Object refreshLock = new Object();
    private volatile Map<String, JwkEntry> keys = Map.of();
    private volatile long fetchedAtMillis;
    private volatile long lastForcedRefreshMillis;

    public TeleportJwksCache(@NotNull String jwksUrl, int ttlSeconds) {
        this(jwksUrl, ttlSeconds, httpSource(jwksUrl, HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(TeleportConstants.JWKS_HTTP_TIMEOUT_SECONDS))
            .build()));
    }

    /**
     * @param documentSource supplies the raw JWKS document; tests use it to avoid a network call
     */
    public TeleportJwksCache(@NotNull String jwksUrl, int ttlSeconds, @NotNull Supplier<String> documentSource) {
        this.jwksUrl = jwksUrl;
        this.ttlMillis = Duration.ofSeconds(Math.max(ttlSeconds, 0)).toMillis();
        this.documentSource = documentSource;
    }

    @NotNull
    @Override
    public JwkEntry getKey(@NotNull String kid) throws Exception {
        Map<String, JwkEntry> snapshot = keys;
        if (!isExpired() && snapshot.containsKey(kid)) {
            return snapshot.get(kid);
        }
        maybeRefresh(kid);
        JwkEntry cached = keys.get(kid);
        if (cached == null) {
            throw new TeleportJwtException("No JWKS key for kid '" + kid + "'");
        }
        return cached;
    }

    private boolean isExpired() {
        return System.currentTimeMillis() - fetchedAtMillis >= ttlMillis;
    }

    /**
     * Refreshes the key set when it is missing/expired, or once per throttle window when a fresh cache does not
     * contain {@code kid} (a rotation). The network fetch runs under {@link #refreshLock} but readers only touch
     * the volatile fields, so a slow fetch never blocks verification threads that already have a usable key.
     */
    private void maybeRefresh(@NotNull String kid) throws Exception {
        synchronized (refreshLock) {
            Map<String, JwkEntry> snapshot = keys;
            long now = System.currentTimeMillis();
            if (snapshot.isEmpty() || now - fetchedAtMillis >= ttlMillis) {
                // Missing or past the TTL: always allowed, this is the normal refresh.
                refresh();
                return;
            }
            if (snapshot.containsKey(kid)) {
                // Another thread refreshed while we waited for the lock.
                return;
            }
            // Unknown kid on an otherwise fresh cache (a rotation): refetch at most once per throttle window,
            // so tokens carrying bogus kids cannot force a fetch on every request.
            if (now - lastForcedRefreshMillis < TeleportConstants.JWKS_MIN_FORCED_REFRESH_INTERVAL_MILLIS) {
                return;
            }
            lastForcedRefreshMillis = now;
            refresh();
        }
    }

    private void refresh() throws Exception {
        String body;
        try {
            body = documentSource.get();
        } catch (Exception e) {
            throw new TeleportJwtException("Failed to fetch JWKS from " + jwksUrl, e);
        }
        Map<String, JwkEntry> parsed = parseJwks(body);
        if (parsed.isEmpty()) {
            throw new TeleportJwtException("JWKS document from " + jwksUrl + " contains no usable keys");
        }
        this.keys = parsed;
        this.fetchedAtMillis = System.currentTimeMillis();
    }

    @NotNull
    static Map<String, JwkEntry> parseJwks(@NotNull String body) {
        JsonObject document = JsonParser.parseString(body).getAsJsonObject();
        JsonArray keyArray = document.getAsJsonArray("keys");
        Map<String, JwkEntry> parsed = new HashMap<>();
        if (keyArray == null) {
            return parsed;
        }
        for (JsonElement element : keyArray) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject jwk = element.getAsJsonObject();
            try {
                JwkEntry entry = parseKey(jwk);
                if (entry != null) {
                    String kid = stringOrEmpty(jwk, "kid");
                    if (parsed.putIfAbsent(kid, entry) != null) {
                        log.warn("Duplicate JWK kid '" + kid + "' in JWKS document; keeping the first key");
                    }
                }
            } catch (Exception e) {
                log.warn("Skipping unreadable JWK", e);
            }
        }
        return parsed;
    }

    @Nullable
    private static JwkEntry parseKey(@NotNull JsonObject jwk) throws Exception {
        String kty = stringOrEmpty(jwk, "kty");
        String alg = stringOrEmpty(jwk, "alg");
        if ("RSA".equals(kty) && TeleportConstants.ALG_RS256.equals(alg)) {
            return new JwkEntry(parseRsaKey(jwk), TeleportConstants.ALG_RS256);
        }
        if ("EC".equals(kty) && "P-256".equals(stringOrEmpty(jwk, "crv")) && TeleportConstants.ALG_ES256.equals(alg)) {
            return new JwkEntry(parseEcKey(jwk), TeleportConstants.ALG_ES256);
        }
        log.warn("Unsupported JWK kty=" + kty + " alg=" + alg);
        return null;
    }

    @NotNull
    private static RSAPublicKey parseRsaKey(@NotNull JsonObject jwk) throws Exception {
        BigInteger modulus = decodeUnsigned(stringOrEmpty(jwk, "n"));
        BigInteger exponent = decodeUnsigned(stringOrEmpty(jwk, "e"));
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        return (RSAPublicKey) key;
    }

    @NotNull
    private static ECPublicKey parseEcKey(@NotNull JsonObject jwk) throws Exception {
        BigInteger x = decodeUnsigned(stringOrEmpty(jwk, "x"));
        BigInteger y = decodeUnsigned(stringOrEmpty(jwk, "y"));
        ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(x, y), P256_PARAMS);
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(spec);
        return (ECPublicKey) key;
    }

    @NotNull
    private static BigInteger decodeUnsigned(@NotNull String base64Url) {
        return new BigInteger(1, Base64.getUrlDecoder().decode(base64Url));
    }

    @NotNull
    private static String stringOrEmpty(@NotNull JsonObject object, @NotNull String name) {
        JsonElement element = object.get(name);
        if (element == null || element.isJsonNull()) {
            return "";
        }
        return element.getAsString();
    }

    @NotNull
    private static Supplier<String> httpSource(@NotNull String jwksUrl, @NotNull HttpClient httpClient) {
        return () -> {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(jwksUrl))
                .timeout(Duration.ofSeconds(TeleportConstants.JWKS_HTTP_TIMEOUT_SECONDS))
                .GET()
                .build();
            HttpResponse<String> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to fetch JWKS from " + jwksUrl, e);
            }
            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                    "JWKS request to " + jwksUrl + " returned HTTP " + response.statusCode());
            }
            return response.body();
        };
    }

    @NotNull
    private static ECParameterSpec loadP256Params() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new IllegalStateException("P-256 curve parameters are not available", e);
        }
    }
}
