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
import io.jsonwebtoken.SignatureException

import java.security.NoSuchAlgorithmException
import java.security.Signature

import org.junit.Test
import static org.junit.Assert.*

class SignatureProviderTest {

    @Test
    void testCreateSignatureInstanceNoSuchAlgorithm() {

        def p = new SignatureProvider(SignatureAlgorithm.HS256, MacProvider.generateKey()) {
            @Override
            protected Signature getSignatureInstance() throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException('foo')
            }
        }

        try {
            p.createSignatureInstance()
            fail()
        } catch (SignatureException se) {
            assertEquals se.cause.message, 'foo'
        }
    }

    @Test
    void testCreateSignatureInstanceNoSuchAlgorithmNonStandardAlgorithm() {

        def p = new SignatureProvider(SignatureAlgorithm.ES512, EllipticCurveProvider.generateKeyPair().getPublic()) {
            @Override
            protected Signature getSignatureInstance() throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException('foo')
            }
        }

        try {
            p.createSignatureInstance()
            fail()
        } catch (SignatureException se) {
            assertEquals se.cause.message, 'foo'
        }
    }

    @Test
    void testCreateSignatureInstanceNoSuchAlgorithmNonStandardAlgorithmWithoutBouncyCastle() {

        def p = new SignatureProvider(SignatureAlgorithm.ES512, EllipticCurveProvider.generateKeyPair().getPublic()) {
            @Override
            protected Signature getSignatureInstance() throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException('foo')
            }

            @Override
            protected boolean isBouncyCastleAvailable() {
                return false
            }
        }

        try {
            p.createSignatureInstance()
            fail()
        } catch (SignatureException se) {
            assertTrue se.message.contains('Try including BouncyCastle in the runtime classpath')
        }
    }
}
