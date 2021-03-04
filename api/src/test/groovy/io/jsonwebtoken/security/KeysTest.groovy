/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.security

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor
import org.powermock.modules.junit4.PowerMockRunner

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPair
import java.security.SecureRandom

import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.*

/**
 * This test class is for cursory API-level testing only (what is available to the API module at build time).
 *
 * The actual implementation assertions are done in KeysImplTest in the impl module.
 */
@RunWith(PowerMockRunner)
@PrepareForTest([SignatureAlgorithms, Keys])
@SuppressStaticInitializationFor("io.jsonwebtoken.security.SignatureAlgorithms")
class KeysTest {

    private static final Random RANDOM = new SecureRandom()

    static byte[] bytes(int sizeInBits) {
        byte[] bytes = new byte[sizeInBits / Byte.SIZE]
        RANDOM.nextBytes(bytes)
        return bytes
    }

    @Test
    void testPrivateCtor() { //for code coverage only
        new Keys()
    }

    @Test
    void testHmacShaKeyForWithNullArgument() {
        try {
            Keys.hmacShaKeyFor(null)
        } catch (InvalidKeyException expected) {
            assertEquals 'SecretKey byte array cannot be null.', expected.message
        }
    }

    @Test
    void testHmacShaKeyForWithWeakKey() {
        int numBytes = 31
        int numBits = numBytes * 8
        try {
            Keys.hmacShaKeyFor(new byte[numBytes])
        } catch (WeakKeyException expected) {
            assertEquals "The specified key byte array is " + numBits + " bits which " +
                    "is not secure enough for any JWT HMAC-SHA algorithm.  The JWT " +
                    "JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a " +
                    "size >= 256 bits (the key size must be greater than or equal to the hash " +
                    "output size).  Consider using the SignatureAlgorithms.HS256.generateKey() method (or " +
                    "HS384.generateKey() or HS512.generateKey()) to create a key guaranteed to be secure enough " +
                    "for your preferred HMAC-SHA algorithm.  See " +
                    "https://tools.ietf.org/html/rfc7518#section-3.2 for more information." as String, expected.message
        }
    }

    @Test
    void testHmacShaWithValidSizes() {
        for (int i : [256, 384, 512]) {
            byte[] bytes = bytes(i)
            def key = Keys.hmacShaKeyFor(bytes)
            assertTrue key instanceof SecretKeySpec
            assertEquals "HmacSHA$i" as String, key.getAlgorithm()
            assertTrue Arrays.equals(bytes, key.getEncoded())
        }
    }

    @Test
    void testHmacShaLargerThan512() {
        def key = Keys.hmacShaKeyFor(bytes(520))
        assertTrue key instanceof SecretKeySpec
        assertEquals 'HmacSHA512', key.getAlgorithm()
        assertTrue key.getEncoded().length * Byte.SIZE >= 512
    }

    @Test
    void testSecretKeyFor() {
        mockStatic(SignatureAlgorithms)

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (name.startsWith('H')) {

                def key = createMock(SecretKey)
                def salg = createMock(SymmetricKeySignatureAlgorithm)

                expect(SignatureAlgorithms.forName(eq(name))).andReturn(salg)
                expect(salg.generateKey()).andReturn(key)
                replay SignatureAlgorithms, salg, key

                assertSame key, Keys.secretKeyFor(alg)

                verify SignatureAlgorithms, salg, key
                reset SignatureAlgorithms, salg, key

            } else {
                def salg = name == 'NONE' ? createMock(io.jsonwebtoken.security.SignatureAlgorithm) : createMock(AsymmetricKeySignatureAlgorithm)
                expect(SignatureAlgorithms.forName(eq(name))).andReturn(salg)
                replay SignatureAlgorithms, salg
                try {
                    Keys.secretKeyFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support shared secret keys." as String, expected.message
                }
                verify SignatureAlgorithms, salg
                reset SignatureAlgorithms, salg
            }
        }
    }

    @Test
    void testKeyPairFor() {
        mockStatic SignatureAlgorithms

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (name.equals('NONE') || name.startsWith('H')) {
                def salg = name == 'NONE' ? createMock(io.jsonwebtoken.security.SignatureAlgorithm) : createMock(SymmetricKeySignatureAlgorithm)
                expect(SignatureAlgorithms.forName(eq(name))).andReturn(salg)
                replay SignatureAlgorithms, salg
                try {
                    Keys.keyPairFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support Key Pairs." as String, expected.message
                }
                verify SignatureAlgorithms, salg
                reset SignatureAlgorithms, salg
            } else {
                def pair = createMock(KeyPair)
                def salg = createMock(AsymmetricKeySignatureAlgorithm)

                expect(SignatureAlgorithms.forName(eq(name))).andReturn(salg)
                expect(salg.generateKeyPair()).andReturn(pair)
                replay SignatureAlgorithms, pair, salg

                assertSame pair, Keys.keyPairFor(alg)

                verify SignatureAlgorithms, pair, salg
                reset SignatureAlgorithms, pair, salg
            }
        }
    }
}
