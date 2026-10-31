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
import io.cloudbeaver.service.teleport.auth.TeleportConstants;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ES256 key and tokens shared by the platform test and the local JWKS endpoint it serves.
 */
final class TeleportTestTokens {
    static final String ISSUER = "localhost.local";
    static final String AUDIENCE = "https://cloudbeaver.localhost.local";
    private static final String KID = "test-ec";

    private static final KeyPair KEY_PAIR = generateKeyPair();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private TeleportTestTokens() {
    }

    static String jwksJson() {
        ECPublicKey key = (ECPublicKey) KEY_PAIR.getPublic();
        return "{\"keys\":[{"
            + "\"kty\":\"EC\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"use\":\"sig\","
            + "\"kid\":\"" + KID + "\","
            + "\"x\":\"" + base64(key.getW().getAffineX()) + "\","
            + "\"y\":\"" + base64(key.getW().getAffineY()) + "\""
            + "}]}";
    }

    static String token(String userName, List<String> roles) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", TeleportConstants.ALG_ES256);
        header.put("kid", KID);
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("aud", AUDIENCE);
        claims.put("username", userName);
        claims.put("roles", roles);
        claims.put("iat", now);
        claims.put("exp", now + 600);

        String signingInput = encode(header) + "." + encode(claims);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(KEY_PAIR.getPrivate());
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] raw = EcSignatureConverter.convertDerToJwsEcSignature(signature.sign());
        return signingInput + "." + ENCODER.encodeToString(raw);
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate test key", e);
        }
    }

    private static String encode(Map<String, Object> value) {
        return ENCODER.encodeToString(new com.google.gson.Gson().toJson(value).getBytes(StandardCharsets.UTF_8));
    }

    private static String base64(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return ENCODER.encodeToString(bytes);
    }
}
