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
import io.jsonwebtoken.lang.Services
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import javax.crypto.SecretKey
import java.security.KeyPair

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.mock
import static org.easymock.EasyMock.same
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.*

/**
 * This test class is for cursory API-level testing only (what is available to the API module at build time).
 *
 * The actual implementation assertions are done in KeysImplTest in the impl module.
 */
@RunWith(PowerMockRunner)
@PrepareForTest([Keys, Services])
class KeysTest {

    static KeyGenerator keyGenerator = mock(KeyGenerator)
    static KeyPairGenerator keyPairGenerator = mock(KeyPairGenerator)

    @BeforeClass
    static void prepareServices() {
        mockStatic(Services)

        expect(Services.loadAllAvailableImplementations(KeyGenerator)).andReturn([keyGenerator]).anyTimes()
        expect(Services.loadAllAvailableImplementations(KeyPairGenerator)).andReturn([keyPairGenerator]).anyTimes()

        replay Services
    }

    @Before
    void reset() {
        reset keyGenerator
        reset keyPairGenerator
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
                    "output size).  Consider using the " + Keys.class.getName() + "#secretKeyFor(SignatureAlgorithm) method " +
                    "to create a key guaranteed to be secure enough for your preferred HMAC-SHA algorithm.  See " +
                    "https://tools.ietf.org/html/rfc7518#section-3.2 for more information." as String, expected.message
        }
    }

    @Test
    void testSecretKeyFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (name.startsWith('H')) {

                def key = createMock(SecretKey)
                expect(keyGenerator.supports(same(alg))).andReturn(true)
                expect(keyGenerator.generateKey(same(alg))).andReturn(key)

                replay keyGenerator, key

                assertSame key, Keys.secretKeyFor(alg)

                verify keyGenerator, key

                reset keyGenerator, key

            } else {
                expect(keyGenerator.supports(same(alg))).andReturn(false)

                replay(keyGenerator)

                try {
                    Keys.secretKeyFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support shared secret keys." as String, expected.message
                    reset keyGenerator
                }
            }
        }

    }

    @Test
    void testKeyPairFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (name.equals('NONE') || name.startsWith('H')) {
                expect(keyPairGenerator.supports(alg)).andReturn(false)

                replay keyPairGenerator

                try {
                    Keys.keyPairFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support Key Pairs." as String, expected.message
                    reset keyPairGenerator
                }
            } else {
                def pair = createMock(KeyPair)
                expect(keyPairGenerator.supports(same(alg))).andReturn(true)
                expect(keyPairGenerator.generateKeyPair(same(alg))).andReturn(pair)

                replay keyPairGenerator, pair

                assertSame pair, Keys.keyPairFor(alg)

                verify keyPairGenerator, pair

                reset keyPairGenerator, pair
            }
        }
    }
}
