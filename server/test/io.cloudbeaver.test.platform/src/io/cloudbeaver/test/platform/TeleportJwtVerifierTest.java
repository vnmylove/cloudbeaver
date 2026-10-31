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
import io.cloudbeaver.service.teleport.auth.JwksProvider;
import io.cloudbeaver.service.teleport.auth.TeleportJwtException;
import io.cloudbeaver.service.teleport.auth.TeleportJwtVerifier;

import org.junit.Assert;
import org.junit.Test;

import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TeleportJwtVerifierTest {

    @Test
    public void acceptsValidRs256Token() throws Exception {
        assertValid(JwtTestSupport.rsa());
    }

    @Test
    public void acceptsValidEs256Token() throws Exception {
        assertValid(JwtTestSupport.ec());
    }

    @Test
    public void rejectsExpiredToken() throws Exception {
        JwtTestSupport support = JwtTestSupport.rsa();
        Map<String, Object> claims = JwtTestSupport.validClaims();
        claims.put("exp", 1L);
        assertRejected(support, support.token(claims));
    }

    @Test
    public void rejectsTokenThatIsNotValidYet() throws Exception {
        JwtTestSupport support = JwtTestSupport.ec();
        Map<String, Object> claims = JwtTestSupport.validClaims();
        claims.put("nbf", System.currentTimeMillis() / 1000 + 3600);
        assertRejected(support, support.token(claims));
    }

    @Test
    public void rejectsWrongIssuer() throws Exception {
        JwtTestSupport support = JwtTestSupport.rsa();
        Map<String, Object> claims = JwtTestSupport.validClaims();
        claims.put("iss", "other-cluster");
        assertRejected(support, support.token(claims));
    }

    @Test
    public void acceptsAudienceAsStringOrArrayAndRejectsAnythingElse() throws Exception {
        JwtTestSupport support = JwtTestSupport.ec();
        Map<String, Object> stringAudience = JwtTestSupport.validClaims();
        verifier(support).verify(support.token(stringAudience));

        Map<String, Object> arrayAudience = JwtTestSupport.validClaims();
        arrayAudience.put("aud", List.of("other", JwtTestSupport.AUDIENCE));
        verifier(support).verify(support.token(arrayAudience));

        Map<String, Object> wrongAudience = JwtTestSupport.validClaims();
        wrongAudience.put("aud", "https://wrong.example");
        assertRejected(support, support.token(wrongAudience));

        Map<String, Object> wrongArrayAudience = JwtTestSupport.validClaims();
        wrongArrayAudience.put("aud", List.of("one", "two"));
        assertRejected(support, support.token(wrongArrayAudience));
    }

    @Test
    public void rejectsTamperedSignature() throws Exception {
        for (JwtTestSupport support : List.of(JwtTestSupport.rsa(), JwtTestSupport.ec())) {
            String token = support.token(JwtTestSupport.validClaims());
            int dot = token.lastIndexOf('.');
            char flipped = token.charAt(dot + 1) == 'A' ? 'B' : 'A';
            String tampered = token.substring(0, dot + 1) + flipped + token.substring(dot + 2);
            assertRejected(support, tampered);
        }
    }

    @Test
    public void rejectsNoneAndHmacAlgorithms() throws Exception {
        JwtTestSupport support = JwtTestSupport.rsa();
        Map<String, Object> claims = JwtTestSupport.validClaims();
        assertRejected(support, support.token("none", JwtTestSupport.KID, claims, support.keyPair.getPrivate()));
        assertRejected(support, support.token("HS256", JwtTestSupport.KID, claims, support.keyPair.getPrivate()));
    }

    @Test
    public void rejectsAlgorithmThatDoesNotMatchKey() throws Exception {
        JwtTestSupport rsa = JwtTestSupport.rsa();
        assertRejected(rsa, unsignedToken("ES256", JwtTestSupport.KID));

        JwtTestSupport ec = JwtTestSupport.ec();
        assertRejected(ec, unsignedToken("RS256", JwtTestSupport.KID));
    }

    @Test
    public void rejectsAlgorithmsOutsideWhitelist() throws Exception {
        JwtTestSupport support = JwtTestSupport.rsa();
        Map<String, Object> claims = JwtTestSupport.validClaims();
        for (String algorithm : List.of("RS384", "RS512", "ES384", "ES512")) {
            assertRejected(support, support.token(algorithm, JwtTestSupport.KID, claims, support.keyPair.getPrivate()));
        }
    }

    @Test
    public void rejectsEs256SignatureThatIsAlreadyDerEncoded() throws Exception {
        JwtTestSupport support = JwtTestSupport.ec();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "ES256");
        header.put("kid", JwtTestSupport.KID);
        String encodedHeader = base64(header);
        String encodedPayload = base64(JwtTestSupport.validClaims());
        String signingInput = encodedHeader + "." + encodedPayload;

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(support.keyPair.getPrivate());
        signature.update(signingInput.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        String derToken = signingInput + "." + base64(signature.sign());
        assertRejected(support, derToken);
    }

    @Test
    public void failsWhenKeyIdIsUnknown() throws Exception {
        JwtTestSupport support = JwtTestSupport.rsa();
        CountingProvider provider = new CountingProvider(support.entry());
        TeleportJwtVerifier verifier = new TeleportJwtVerifier(
            provider, JwtTestSupport.ISSUER, JwtTestSupport.AUDIENCE, 60);
        Assert.assertThrows(
            TeleportJwtException.class,
            () -> verifier.verify(support.token(JwtTestSupport.validClaims())));
        Assert.assertEquals(1, provider.lookups);
    }

    @Test
    public void acceptsTokenWithoutKeyIdWhenEmptyKeyIdIsPublished() throws Exception {
        JwtTestSupport support = JwtTestSupport.ec();
        JwksProvider provider = kid -> {
            Assert.assertEquals("", kid);
            return support.entry();
        };
        TeleportJwtVerifier verifier = new TeleportJwtVerifier(
            provider, JwtTestSupport.ISSUER, JwtTestSupport.AUDIENCE, 60);

        String token = support.token("ES256", "", JwtTestSupport.validClaims(), support.keyPair.getPrivate());
        Assert.assertEquals("alice", verifier.verify(token).get("username"));

        String withoutKid = tokenWithoutKid(support);
        Assert.assertEquals("alice", verifier.verify(withoutKid).get("username"));
    }

    private void assertValid(JwtTestSupport support) throws Exception {
        Map<String, Object> claims = verifier(support).verify(support.token(JwtTestSupport.validClaims()));
        Assert.assertEquals("alice", claims.get("username"));
        Assert.assertEquals(List.of("editor", "admin"), claims.get("roles"));
    }

    private TeleportJwtVerifier verifier(JwtTestSupport support) {
        return new TeleportJwtVerifier(kid -> support.entry(), JwtTestSupport.ISSUER, JwtTestSupport.AUDIENCE, 60);
    }

    private void assertRejected(JwtTestSupport support, String token) {
        Assert.assertThrows(TeleportJwtException.class, () -> verifier(support).verify(token));
    }

    private String tokenWithoutKid(JwtTestSupport support) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", support.algorithm);
        String encodedHeader = base64(header);
        String encodedPayload = base64(JwtTestSupport.validClaims());
        String signingInput = encodedHeader + "." + encodedPayload;
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(support.keyPair.getPrivate());
        signature.update(signingInput.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] raw = EcSignatureConverter.convertDerToJwsEcSignature(signature.sign());
        return signingInput + "." + base64(raw);
    }

    private static String unsignedToken(String algorithm, String kid) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", algorithm);
        header.put("kid", kid);
        return base64(header) + "." + base64(JwtTestSupport.validClaims()) + "." + base64(new byte[] {1, 2, 3});
    }

    private static String base64(Object value) {
        byte[] bytes = value instanceof byte[] raw
            ? raw
            : new com.google.gson.Gson().toJson(value).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static final class CountingProvider implements JwksProvider {
        private final JwkEntry entry;
        private int lookups;

        private CountingProvider(JwkEntry entry) {
            this.entry = entry;
        }

        @Override
        public JwkEntry getKey(String kid) throws TeleportJwtException {
            lookups++;
            if (lookups == 1) {
                throw new TeleportJwtException("unknown kid");
            }
            return entry;
        }
    }
}
