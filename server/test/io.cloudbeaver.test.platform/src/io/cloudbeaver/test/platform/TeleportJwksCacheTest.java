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
package io.cloudbeaver.test.platform;

import io.cloudbeaver.service.auth.teleport.JwkEntry;
import io.cloudbeaver.service.auth.teleport.TeleportConstants;
import io.cloudbeaver.service.auth.teleport.TeleportJwksCache;
import io.cloudbeaver.service.auth.teleport.TeleportJwtException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public class TeleportJwksCacheTest {
    private static final String JWKS_URL = "https://teleport.example/.well-known/jwks.json";

    @Test
    public void parsesRsaKey() throws Exception {
        RSAPublicKey key = (RSAPublicKey) KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
        String jwks = jwks("{"
            + "\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"rsa-1\","
            + "\"n\":\"" + base64(key.getModulus()) + "\","
            + "\"e\":\"" + base64(key.getPublicExponent()) + "\"}");

        JwkEntry entry = cache(jwks, new AtomicInteger()).getKey("rsa-1");
        Assertions.assertEquals(TeleportConstants.ALG_RS256, entry.alg());
        Assertions.assertEquals(key, entry.publicKey());
    }

    @Test
    public void parsesEcKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
        String jwks = jwks("{"
            + "\"kty\":\"EC\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"kid\":\"ec-1\","
            + "\"x\":\"" + base64(key.getW().getAffineX()) + "\","
            + "\"y\":\"" + base64(key.getW().getAffineY()) + "\"}");

        JwkEntry entry = cache(jwks, new AtomicInteger()).getKey("ec-1");
        Assertions.assertEquals(TeleportConstants.ALG_ES256, entry.alg());
        ECPublicKey parsed = (ECPublicKey) entry.publicKey();
        Assertions.assertEquals(key.getW().getAffineX(), parsed.getW().getAffineX());
        Assertions.assertEquals(key.getW().getAffineY(), parsed.getW().getAffineY());
    }

    @Test
    public void keepsKeyPublishedWithEmptyKeyId() throws Exception {
        String key = ecKey("real");
        String duplicate = key.replace("\"kid\":\"real\"", "\"kid\":\"\"");
        TeleportJwksCache jwksCache = cache(jwks(key + "," + duplicate), new AtomicInteger());

        Assertions.assertEquals(jwksCache.getKey("real").publicKey(), jwksCache.getKey("").publicKey());
    }

    @Test
    public void skipsUnsupportedKeys() throws Exception {
        String unsupported = "{\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"ed\",\"x\":\"abcd\"}";
        TeleportJwksCache jwksCache = cache(jwks(unsupported + "," + ecKey("ec")), new AtomicInteger());
        Assertions.assertEquals(TeleportConstants.ALG_ES256, jwksCache.getKey("ec").alg());
        Assertions.assertThrows(TeleportJwtException.class, () -> jwksCache.getKey("ed"));
    }

    @Test
    public void reusesKeysUntilTtlExpires() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        TeleportJwksCache jwksCache = cache(jwks(ecKey("ec")), requests);
        jwksCache.getKey("ec");
        jwksCache.getKey("ec");
        Assertions.assertEquals(1, requests.get());
    }

    @Test
    public void refreshesOnceWhenKeyIdIsMissing() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> body = new AtomicReference<>(jwks(ecKey("first")));
        TeleportJwksCache jwksCache = cache(body::get, requests);
        jwksCache.getKey("first");

        body.set(jwks(ecKey("rotated")));
        Assertions.assertEquals(TeleportConstants.ALG_ES256, jwksCache.getKey("rotated").alg());
        Assertions.assertEquals(2, requests.get());
    }

    @Test
    public void failsWhenJwksCannotBeFetched() {
        Supplier<String> failing = () -> {
            throw new IllegalStateException("timed out");
        };
        TeleportJwksCache jwksCache = new TeleportJwksCache(JWKS_URL, 3600, failing);
        Assertions.assertThrows(TeleportJwtException.class, () -> jwksCache.getKey("any"));
    }

    @Test
    public void failsWhenDocumentHasNoUsableKeys() {
        TeleportJwksCache jwksCache = cache("{\"keys\":[]}", new AtomicInteger());
        Assertions.assertThrows(TeleportJwtException.class, () -> jwksCache.getKey("any"));
    }

    private static TeleportJwksCache cache(String body, AtomicInteger requests) {
        return cache(() -> body, requests);
    }

    private static TeleportJwksCache cache(Supplier<String> body, AtomicInteger requests) {
        return new TeleportJwksCache(JWKS_URL, 3600, () -> {
            requests.incrementAndGet();
            return body.get();
        });
    }

    private static String jwks(String keys) {
        return "{\"keys\":[" + keys + "]}";
    }

    private static String ecKey(String kid) {
        return "{\"kty\":\"EC\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"kid\":\"" + kid + "\","
            + "\"x\":\"VlVKmPLOOJLipdE1xo9F6H2_lVqBB7__6ahPd6fV-dg\","
            + "\"y\":\"0lL0G0OTQl0P9vE1Cb9tj3agYyReYYjMJb4AAPrAX80\"}";
    }

    private static String base64(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
