/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import org.junit.Before
import org.junit.Test

import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import static org.junit.Assert.*

class ConcatKDFTest {

    ConcatKDF CONCAT_KDF = EcdhKeyAlgorithm.CONCAT_KDF

    private byte[] Z

    @Before
    void setUp() {
        Z = new byte[16]
        Randoms.secureRandom().nextBytes(Z)
    }

    @Test
    void testNullOtherInfo() {
        final int derivedKeyBitLength = 256
        final byte[] OtherInfo = null

        // exactly 1 Concat KDF iteration - derived key bit length of 256 is same as SHA-256 digest length:
        def md = MessageDigest.getInstance("SHA-256")
        md.update([0, 0, 0, 1] as byte[])
        md.update(Z)
        md.update(Bytes.EMPTY) // null OtherInfo should equate to a Bytes.EMPTY argument here
        byte[] digest = md.digest()

        SecretKey key = CONCAT_KDF.deriveKey(Z, derivedKeyBitLength, OtherInfo)
        byte[] derived = key.getEncoded()
        assertNotNull(key)
        assertArrayEquals(digest, derived)
    }

    @Test
    void testEmptyOtherInfo() {
        final int derivedKeyBitLength = 256
        final byte[] OtherInfo = Bytes.EMPTY

        // exactly 1 Concat KDF iteration - derived key bit length of 256 is same as SHA-256 digest length:
        def md = MessageDigest.getInstance("SHA-256")
        md.update([0, 0, 0, 1] as byte[])
        md.update(Z)
        md.update(Bytes.EMPTY) // empty OtherInfo should equate to a Bytes.EMPTY argument here
        byte[] digest = md.digest()

        SecretKey key = CONCAT_KDF.deriveKey(Z, derivedKeyBitLength, OtherInfo)
        byte[] derived = key.getEncoded()
        assertNotNull(key)
        assertArrayEquals(digest, derived)
    }

    @Test
    void testPopulatedOtherInfo() {
        final int derivedKeyBitLength = 256
        final byte[] OtherInfo = 'whatever'.getBytes(StandardCharsets.UTF_8)

        // exactly 1 Concat KDF iteration - derived key bit length of 256 is same as SHA-256 digest length:
        def md = MessageDigest.getInstance("SHA-256")
        md.update([0, 0, 0, 1] as byte[])
        md.update(Z)
        md.update(OtherInfo) // ensure OtherInfo is included in the digest
        byte[] digest = md.digest()

        SecretKey key = CONCAT_KDF.deriveKey(Z, derivedKeyBitLength, OtherInfo)
        byte[] derived = key.getEncoded()
        assertNotNull(key)
        assertArrayEquals(digest, derived)
    }

    @Test
    void testNonPositiveBitLength() {
        try {
            CONCAT_KDF.deriveKey(Z, 0, null)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'derivedKeyBitLength must be a positive integer.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testDerivedKeyBitLengthBiggerThanJdkMax() {
        byte[] Z = new byte[16]
        long bitLength = Long.valueOf(Integer.MAX_VALUE) * 8L + 8L // one byte more than java byte arrays can handle
        try {
            CONCAT_KDF.deriveKey(Z, bitLength, null)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'derivedKeyBitLength may not exceed 17179869176 bits (2147483647 bytes). ' +
                    'Specified size: 17179869184 bits (2147483648 bytes).'
            assertEquals msg, expected.getMessage()
        }
    }
}
