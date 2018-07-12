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

import io.jsonwebtoken.JwtException
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SignatureException
import org.junit.Test

import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class EllipticCurveSignerTest {

    @Test
    void testConstructorWithoutECAlg() {
        try {
            new EllipticCurveSigner(SignatureAlgorithm.HS256, MacProvider.generateKey());
            fail('EllipticCurveSigner should reject non ECPrivateKeys');
        } catch (IllegalArgumentException expected) {
            assertEquals expected.message, 'SignatureAlgorithm must be an Elliptic Curve algorithm.';
        }
    }

    @Test
    void testConstructorWithoutECPrivateKey() {
        def key = MacProvider.generateKey()
        try {
            new EllipticCurveSigner(SignatureAlgorithm.ES256, key);
            fail('EllipticCurveSigner should reject non ECPrivateKey instances.')
        } catch (IllegalArgumentException expected) {
            assertEquals expected.message, "Elliptic Curve signatures must be computed using an EC PrivateKey.  The specified key of " +
            "type " + key.getClass().getName() + " is not an EC PrivateKey.";
        }
    }

    @Test
    void testDoSignWithInvalidKeyException() {

        KeyPair kp = EllipticCurveProvider.generateKeyPair()
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final InvalidKeyException ex = new InvalidKeyException(msg)

        def signer = new EllipticCurveSigner(SignatureAlgorithm.ES256, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)

        try {
            signer.sign(bytes)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Invalid Elliptic Curve PrivateKey. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testDoSignWithJoseSignatureFormatException() {

        KeyPair kp = EllipticCurveProvider.generateKeyPair()
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final JwtException ex = new JwtException(msg)

        def signer = new EllipticCurveSigner(SignatureAlgorithm.ES256, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException, JwtException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)

        try {
            signer.sign(bytes)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Unable to convert signature to JOSE format. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testDoSignWithJdkSignatureException() {

        KeyPair kp = EllipticCurveProvider.generateKeyPair()
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final java.security.SignatureException ex = new java.security.SignatureException(msg)

        def signer = new EllipticCurveSigner(SignatureAlgorithm.ES256, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        SignatureProvider.DEFAULT_SECURE_RANDOM.nextBytes(bytes)

        try {
            signer.sign(bytes)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Unable to calculate signature using Elliptic Curve PrivateKey. ' + msg
            assertSame se.cause, ex
        }
    }
}
