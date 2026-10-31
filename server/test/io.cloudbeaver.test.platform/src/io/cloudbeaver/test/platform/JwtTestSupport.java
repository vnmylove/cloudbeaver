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

import io.cloudbeaver.service.teleport.auth.EcSignatureConverter;
import io.cloudbeaver.service.teleport.auth.JwkEntry;
import io.cloudbeaver.service.teleport.auth.TeleportConstants;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds signed JWTs for tests. ES256 signatures are stored in the raw JWS form Teleport publishes.
 */
final class JwtTestSupport {
    static final String KID = "test-key";
    static final String ISSUER = "localhost.local";
    static final String AUDIENCE = "https://cloudbeaver.localhost.local";

    private static final Gson GSON = new Gson();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    final KeyPair keyPair;
    final String algorithm;

    private JwtTestSupport(KeyPair keyPair, String algorithm) {
        this.keyPair = keyPair;
        this.algorithm = algorithm;
    }

    static JwtTestSupport rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return new JwtTestSupport(generator.generateKeyPair(), TeleportConstants.ALG_RS256);
    }

    static JwtTestSupport ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return new JwtTestSupport(generator.generateKeyPair(), TeleportConstants.ALG_ES256);
    }

    PublicKey publicKey() {
        return keyPair.getPublic();
    }

    JwkEntry entry() {
        return new JwkEntry(publicKey(), algorithm);
    }

    String token(Map<String, Object> claims) throws Exception {
        return token(algorithm, KID, claims, keyPair.getPrivate());
    }

    String token(String headerAlgorithm, String kid, Map<String, Object> claims, PrivateKey privateKey) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", headerAlgorithm);
        header.put("kid", kid);
        String encodedHeader = encode(header);
        String encodedPayload = encode(claims);
        String signingInput = encodedHeader + "." + encodedPayload;
        return signingInput + "." + ENCODER.encodeToString(sign(headerAlgorithm, signingInput, privateKey));
    }

    static Map<String, Object> validClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("aud", AUDIENCE);
        claims.put("username", "alice");
        claims.put("roles", java.util.List.of("editor", "admin"));
        long now = Instant.now().getEpochSecond();
        claims.put("iat", now);
        claims.put("nbf", now - 10);
        claims.put("exp", now + 600);
        return claims;
    }

    private static byte[] sign(String headerAlgorithm, String signingInput, PrivateKey privateKey) throws Exception {
        String jcaAlgorithm = TeleportConstants.ALG_ES256.equals(headerAlgorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        Signature signature = Signature.getInstance(jcaAlgorithm);
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] signed = signature.sign();
        if (TeleportConstants.ALG_ES256.equals(headerAlgorithm)) {
            return EcSignatureConverter.convertDerToJwsEcSignature(signed);
        }
        return signed;
    }

    private static String encode(Map<String, Object> value) {
        return ENCODER.encodeToString(GSON.toJson(value).getBytes(StandardCharsets.UTF_8));
    }
}
