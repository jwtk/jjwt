/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test

import java.security.KeyPair
import java.security.NoSuchProviderException
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

import static org.junit.Assert.*

class EllipticCurveProviderTest {

    @Test
    void testGenerateKeyPair() {
        KeyPair pair = EllipticCurveProvider.generateKeyPair()
        assertNotNull pair
        assertTrue pair.public instanceof ECPublicKey
        assertTrue pair.private instanceof ECPrivateKey
    }

    @Test
    void testGenerateKeyPairWithInvalidProviderName() {
        try {
            EllipticCurveProvider.generateKeyPair("ECDSA", "Foo", SignatureAlgorithm.ES256, null)
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.message, "Unable to generate Elliptic Curve KeyPair: no such provider: Foo"
            assertTrue ise.cause instanceof NoSuchProviderException
        }
    }

    @Test
    void testGenerateKeyPairWithNullAlgorithm() {
        try {
            EllipticCurveProvider.generateKeyPair("ECDSA", "Foo", null, null)
            fail()
        } catch (IllegalArgumentException ise) {
            assertEquals ise.message, "SignatureAlgorithm argument cannot be null."
        }
    }

    @Test
    void testGenerateKeyPairWithNonEllipticCurveAlgorithm() {
        try {
            EllipticCurveProvider.generateKeyPair("ECDSA", "Foo", SignatureAlgorithm.HS256, null)
            fail()
        } catch (IllegalArgumentException ise) {
            assertEquals ise.message, "SignatureAlgorithm argument must represent an Elliptic Curve algorithm."
        }
    }
}
