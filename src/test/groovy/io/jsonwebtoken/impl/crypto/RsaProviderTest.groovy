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

import java.security.InvalidAlgorithmParameterException
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PSSParameterSpec

import org.junit.Test
import static org.junit.Assert.*

class RsaProviderTest {

    @Test
    void testGenerateKeyPair() {
        KeyPair pair = RsaProvider.generateKeyPair()
        assertNotNull pair
        assertTrue pair.public instanceof RSAPublicKey
        assertTrue pair.private instanceof RSAPrivateKey
    }

    @Test
    void testGenerateKeyPairWithInvalidProviderName() {
        try {
            RsaProvider.generateKeyPair('foo', 1024, SignatureProvider.DEFAULT_SECURE_RANDOM)
            fail()
        } catch (IllegalStateException ise) {
            assertTrue ise.message.startsWith("Unable to obtain an RSA KeyPairGenerator: ")
        }
    }

    @Test
    void testCreateSignatureInstanceWithInvalidPSSParameterSpecAlgorithm() {

        def p = new RsaProvider(SignatureAlgorithm.PS256, RsaProvider.generateKeyPair(512).public) {
            @Override
            protected void doSetParameter(Signature sig, PSSParameterSpec spec) throws InvalidAlgorithmParameterException {
                throw new InvalidAlgorithmParameterException('foo')
            }
        }

        try {
            p.createSignatureInstance()
            fail()
        } catch (SignatureException se) {
            assertTrue se.message.startsWith('Unsupported RSASSA-PSS parameter')
            assertEquals se.cause.message, 'foo'
        }
    }
}
