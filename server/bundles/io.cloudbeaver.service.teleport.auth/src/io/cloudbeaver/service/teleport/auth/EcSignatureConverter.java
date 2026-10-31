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

import org.jkiss.code.NotNull;

import java.util.Arrays;

/**
 * Converts a JWS ECDSA signature (raw concatenation of r and s) into the DER encoding
 * expected by {@code Signature.getInstance("SHA256withECDSA")}.
 */
public final class EcSignatureConverter {
    private static final int P256_COORDINATE_LENGTH = 32;

    private EcSignatureConverter() {
    }

    @NotNull
    public static byte[] convertJwsEcSignatureToDer(@NotNull byte[] jwsSignature) {
        if (jwsSignature.length != P256_COORDINATE_LENGTH * 2) {
            throw new IllegalArgumentException(
                "ES256 signature must be " + (P256_COORDINATE_LENGTH * 2) + " bytes, got " + jwsSignature.length);
        }
        byte[] r = encodePositiveInteger(jwsSignature, 0, P256_COORDINATE_LENGTH);
        byte[] s = encodePositiveInteger(jwsSignature, P256_COORDINATE_LENGTH, P256_COORDINATE_LENGTH);
        int contentLength = r.length + s.length;
        byte[] der = new byte[2 + contentLength];
        der[0] = 0x30;
        der[1] = (byte) contentLength;
        System.arraycopy(r, 0, der, 2, r.length);
        System.arraycopy(s, 0, der, 2 + r.length, s.length);
        return der;
    }

    /**
     * Inverse of {@link #convertJwsEcSignatureToDer(byte[])}, used to check the conversion round-trips.
     */
    @NotNull
    public static byte[] convertDerToJwsEcSignature(@NotNull byte[] der) {
        if (der.length < 2 || der[0] != 0x30) {
            throw new IllegalArgumentException("Not a DER sequence");
        }
        int contentLength = der[1] & 0xff;
        if (der.length != 2 + contentLength) {
            throw new IllegalArgumentException("DER sequence length does not match");
        }
        byte[] r = readInteger(der, 2);
        byte[] s = readInteger(der, 2 + r.length);
        byte[] raw = new byte[P256_COORDINATE_LENGTH * 2];
        writeFixed(raw, 0, r);
        writeFixed(raw, P256_COORDINATE_LENGTH, s);
        return raw;
    }

    @NotNull
    private static byte[] encodePositiveInteger(@NotNull byte[] source, int offset, int length) {
        int start = offset;
        int end = offset + length;
        while (start < end - 1 && source[start] == 0) {
            start++;
        }
        boolean needsPadding = (source[start] & 0x80) != 0;
        int valueLength = end - start;
        byte[] encoded = new byte[2 + (needsPadding ? 1 : 0) + valueLength];
        encoded[0] = 0x02;
        encoded[1] = (byte) (valueLength + (needsPadding ? 1 : 0));
        int valueOffset = 2;
        if (needsPadding) {
            encoded[valueOffset++] = 0x00;
        }
        System.arraycopy(source, start, encoded, valueOffset, valueLength);
        return encoded;
    }

    @NotNull
    private static byte[] readInteger(@NotNull byte[] der, int offset) {
        if (der[offset] != 0x02) {
            throw new IllegalArgumentException("Expected DER integer");
        }
        int length = der[offset + 1] & 0xff;
        return Arrays.copyOfRange(der, offset, offset + 2 + length);
    }

    private static void writeFixed(@NotNull byte[] target, int targetOffset, @NotNull byte[] derInteger) {
        int length = derInteger[1] & 0xff;
        int valueOffset = 2;
        if (length > 0 && derInteger[2] == 0x00) {
            valueOffset++;
            length--;
        }
        int padding = P256_COORDINATE_LENGTH - length;
        System.arraycopy(derInteger, valueOffset, target, targetOffset + padding, length);
    }
}
