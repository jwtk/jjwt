/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.SecretKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertEquals

class DefaultRsaKeyAlgorithmTest {

    static final algs = [Jwts.KEY.RSA1_5, Jwts.KEY.RSA_OAEP, Jwts.KEY.RSA_OAEP_256] as List<DefaultRsaKeyAlgorithm>

    @Test
    void testValidateNonRSAKey() {
        SecretKey key = Jwts.KEY.A128KW.key().build()
        for (DefaultRsaKeyAlgorithm alg : algs) {
            try {
                alg.validate(key, true)
            } catch (InvalidKeyException e) {
                assertEquals 'Invalid RSA key algorithm name.', e.getMessage()
            }
            try {
                alg.validate(key, false)
            } catch (InvalidKeyException e) {
                assertEquals 'Invalid RSA key algorithm name.', e.getMessage()
            }
        }
    }

    @Test
    void testValidateRsaKeyWithoutKeySize() {
        for (def alg : algs) {
            // if RSAKey interface isn't exposed (e.g. PKCS11 or HSM), don't error:
            alg.validate(new TestPublicKey(algorithm: 'RSA'), true)
            alg.validate(new TestPrivateKey(algorithm: 'RSA'), false)
        }
    }

    @Test
    void testPssKey() {
        for (DefaultRsaKeyAlgorithm alg : algs) {
            RSAPublicKey key = createMock(RSAPublicKey)
            expect(key.getAlgorithm()).andStubReturn(RsaSignatureAlgorithm.PSS_JCA_NAME)
            replay(key)
            try {
                alg.validate(key, true)
            } catch (InvalidKeyException expected) {
                String msg = 'RSASSA-PSS keys may not be used for encryption, only digital signature algorithms.'
                assertEquals msg, expected.getMessage()
            }
            verify(key)
        }
    }

    @Test
    void testPssOidKey() {
        for (DefaultRsaKeyAlgorithm alg : algs) {
            RSAPublicKey key = createMock(RSAPublicKey)
            expect(key.getAlgorithm()).andStubReturn(RsaSignatureAlgorithm.PSS_OID)
            replay(key)
            try {
                alg.validate(key, true)
            } catch (InvalidKeyException expected) {
                String msg = 'RSASSA-PSS keys may not be used for encryption, only digital signature algorithms.'
                assertEquals msg, expected.getMessage()
            }
            verify(key)
        }
    }

    @Test
    void testWeakEncryptionKey() {
        for (DefaultRsaKeyAlgorithm alg : algs) {
            RSAPublicKey key = createMock(RSAPublicKey)
            expect(key.getAlgorithm()).andStubReturn("RSA")
            expect(key.getModulus()).andReturn(BigInteger.ONE)
            replay(key)
            try {
                alg.validate(key, true)
            } catch (WeakKeyException e) {
                String id = alg.getId()
                String section = id.equals("RSA1_5") ? "4.2" : "4.3"
                String msg = "The RSA encryption key size (aka modulus bit length) is 1 bits which is not secure " +
                        "enough for the $id algorithm. The JWT JWA Specification (RFC 7518, Section $section) " +
                        "states that RSA keys MUST have a size >= 2048 bits. " +
                        "See https://www.rfc-editor.org/rfc/rfc7518.html#section-$section for more information."
                assertEquals(msg, e.getMessage())
            }
            verify(key)
        }
    }

    @Test
    void testWeakDecryptionKey() {
        for (DefaultRsaKeyAlgorithm alg : algs) {
            RSAPrivateKey key = createMock(RSAPrivateKey)
            expect(key.getAlgorithm()).andStubReturn("RSA")
            expect(key.getModulus()).andReturn(BigInteger.ONE)
            replay(key)
            try {
                alg.validate(key, false)
            } catch (WeakKeyException e) {
                String id = alg.getId()
                String section = id.equals("RSA1_5") ? "4.2" : "4.3"
                String msg = "The RSA decryption key size (aka modulus bit length) is 1 bits which is not secure " +
                        "enough for the $id algorithm. The JWT JWA Specification (RFC 7518, Section $section) " +
                        "states that RSA keys MUST have a size >= 2048 bits. " +
                        "See https://www.rfc-editor.org/rfc/rfc7518.html#section-$section for more information."
                assertEquals(msg, e.getMessage())
            }
            verify(key)
        }
    }
}
