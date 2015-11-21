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

import javax.crypto.spec.SecretKeySpec
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey

import org.junit.Test
import static org.junit.Assert.*

class RsaSignerTest {

    private static final Random rng = new Random(); //doesn't need to be secure - we're just testing

    @Test
    void testConstructorWithoutRsaAlg() {

        byte[] bytes = new byte[16]
        rng.nextBytes(bytes)
        SecretKeySpec key = new SecretKeySpec(bytes, 'HmacSHA256')

        try {
            new RsaSigner(SignatureAlgorithm.HS256, key);
            fail('RsaSigner should reject non RSA algorithms.')
        } catch (IllegalArgumentException expected) {
            assertEquals expected.message, 'SignatureAlgorithm must be an RSASSA or RSASSA-PSS algorithm.';
        }
    }

    @Test
    void testConstructorWithoutPrivateKey() {

        byte[] bytes = new byte[16]
        rng.nextBytes(bytes)
        SecretKeySpec key = new SecretKeySpec(bytes, 'HmacSHA256')

        try {
            //noinspection GroovyResultOfObjectAllocationIgnored
            new RsaSigner(SignatureAlgorithm.RS256, key);
            fail('RsaSigner should reject non RSAPrivateKey instances.')
        } catch (IllegalArgumentException expected) {
            assertEquals expected.message, "RSA signatures must be computed using an RSA PrivateKey.  The specified key of type " +
                    key.getClass().getName() + " is not an RSA PrivateKey.";
        }
    }

    @Test
    void testConstructorWithoutRSAKey() {

        //private key, but not an RSAKey instance:
        PrivateKey key = new PrivateKey() {
            @Override
            String getAlgorithm() {
                return null
            }

            @Override
            String getFormat() {
                return null
            }

            @Override
            byte[] getEncoded() {
                return new byte[0]
            }
        }

        try {
            //noinspection GroovyResultOfObjectAllocationIgnored
            new RsaSigner(SignatureAlgorithm.RS256, key);
            fail('RsaSigner should reject non RSAPrivateKey instances.')
        } catch (IllegalArgumentException expected) {
            assertEquals expected.message, "RSA signatures must be computed using an RSA PrivateKey.  The specified key of type " +
                    key.getClass().getName() + " is not an RSA PrivateKey.";
        }
    }

    @Test
    void testDoSignWithInvalidKeyException() {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final InvalidKeyException ex = new InvalidKeyException(msg)

        RsaSigner signer = new RsaSigner(SignatureAlgorithm.RS256, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        rng.nextBytes(bytes)

        try {
            signer.sign(bytes)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Invalid RSA PrivateKey. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testDoSignWithJdkSignatureException() {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final java.security.SignatureException ex = new java.security.SignatureException(msg)

        RsaSigner signer = new RsaSigner(SignatureAlgorithm.RS256, privateKey) {
            @Override
            protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
                throw ex
            }
        }

        byte[] bytes = new byte[16]
        rng.nextBytes(bytes)

        try {
            signer.sign(bytes)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Unable to calculate signature using RSA PrivateKey. ' + msg
            assertSame se.cause, ex
        }
    }

    @Test
    void testSignSuccessful() {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PrivateKey privateKey = kp.getPrivate();

        byte[] bytes = new byte[16]
        rng.nextBytes(bytes)

        RsaSigner signer = new RsaSigner(SignatureAlgorithm.RS256, privateKey);
        byte[] out1 = signer.sign(bytes)

        byte[] out2 = signer.sign(bytes)

        assertTrue(MessageDigest.isEqual(out1, out2))
    }
}
