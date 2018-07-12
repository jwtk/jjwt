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
import org.junit.Test

import java.security.*

import static org.junit.Assert.*

class RsaSignatureValidatorTest {

    private static final Random rng = new Random(); //doesn't need to be secure - we're just testing

    @Test
    void testConstructorWithNonRsaKey() {
        try {
            new RsaSignatureValidator(SignatureAlgorithm.RS256, MacProvider.generateKey());
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "RSA Signature validation requires either a RSAPublicKey or RSAPrivateKey instance.", iae.message
        }
    }

    @Test
    void testDoVerifyWithInvalidKeyException() {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String msg = 'foo'
        final InvalidKeyException ex = new InvalidKeyException(msg)

        RsaSignatureValidator v = new RsaSignatureValidator(SignatureAlgorithm.RS256, publicKey) {
            @Override
            protected boolean doVerify(Signature sig, PublicKey pk, byte[] data, byte[] signature) throws InvalidKeyException, java.security.SignatureException {
                throw ex;
            }
        }

        byte[] bytes = new byte[16]
        byte[] signature = new byte[16]
        rng.nextBytes(bytes)
        rng.nextBytes(signature)

        try {
            v.isValid(bytes, signature)
            fail();
        } catch (SignatureException se) {
            assertEquals se.message, 'Unable to verify RSA signature using configured PublicKey. ' + msg
            assertSame se.cause, ex
        }
    }
}
