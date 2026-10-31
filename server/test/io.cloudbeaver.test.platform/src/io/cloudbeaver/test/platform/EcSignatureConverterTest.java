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

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class EcSignatureConverterTest {

    @Test
    public void convertsSignatureThatJdkCanVerify() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var keyPair = generator.generateKeyPair();

        byte[] message = "teleport".getBytes();
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] der = signer.sign();

        byte[] raw = EcSignatureConverter.convertDerToJwsEcSignature(der);
        Assert.assertEquals(64, raw.length);
        byte[] converted = EcSignatureConverter.convertJwsEcSignatureToDer(raw);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        Assert.assertTrue(verifier.verify(converted));
    }

    @Test
    public void padsCoordinateWhoseHighBitIsSet() {
        byte[] raw = new byte[64];
        raw[0] = (byte) 0x80;
        raw[31] = 0x01;
        raw[32] = 0x01;

        byte[] der = EcSignatureConverter.convertJwsEcSignatureToDer(raw);
        Assert.assertEquals(0x02, der[2]);
        Assert.assertEquals(33, der[3]);
        Assert.assertEquals(0x00, der[4]);
        Assert.assertEquals((byte) 0x80, der[5]);
    }

    @Test
    public void stripsLeadingZerosFromCoordinate() {
        byte[] raw = new byte[64];
        raw[30] = 0x00;
        raw[31] = 0x05;

        byte[] der = EcSignatureConverter.convertJwsEcSignatureToDer(raw);
        Assert.assertEquals(0x02, der[2]);
        Assert.assertEquals(1, der[3] & 0xff);
        Assert.assertEquals(0x05, der[4]);
    }

    @Test
    public void rejectsUnexpectedLength() {
        Assert.assertThrows(
            IllegalArgumentException.class,
            () -> EcSignatureConverter.convertJwsEcSignatureToDer(new byte[63]));
    }

    @Test
    public void roundTripsRandomSignatures() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var keyPair = generator.generateKeyPair();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 100; i++) {
            byte[] message = new byte[32];
            random.nextBytes(message);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(message);
            byte[] raw = EcSignatureConverter.convertDerToJwsEcSignature(signer.sign());
            byte[] restored = EcSignatureConverter.convertDerToJwsEcSignature(
                EcSignatureConverter.convertJwsEcSignatureToDer(raw));
            Assert.assertTrue(Arrays.equals(raw, restored));
        }
    }
}
