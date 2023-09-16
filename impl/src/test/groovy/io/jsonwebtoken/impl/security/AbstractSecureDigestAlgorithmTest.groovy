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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SecureRequest
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.security.VerifySecureDigestRequest
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.*

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

class AbstractSecureDigestAlgorithmTest {

    @Test
    void testSignAndVerifyWithExplicitProvider() {
        Provider provider = Security.getProvider('BC')
        def pair = Jwts.SIG.RS256.keyPair().build()
        byte[] data = 'foo'.getBytes(StandardCharsets.UTF_8)
        byte[] signature = Jwts.SIG.RS256.digest(new DefaultSecureRequest<byte[], PrivateKey>(data, provider, null, pair.getPrivate()))
        assertTrue Jwts.SIG.RS256.verify(new DefaultVerifySecureDigestRequest<PublicKey>(data, provider, null, pair.getPublic(), signature))
    }

    @Test
    void testSignFailsWithAnExternalException() {
        def pair = Jwts.SIG.RS256.keyPair().build()
        def ise = new IllegalStateException('foo')
        def alg = new TestAbstractSecureDigestAlgorithm() {
            @Override
            protected byte[] doDigest(SecureRequest request) throws Exception {
                throw ise
            }
        }
        try {
            alg.digest(new DefaultSecureRequest('foo'.getBytes(StandardCharsets.UTF_8), null, null, pair.getPrivate()))
        } catch (SignatureException e) {
            assertTrue e.getMessage().startsWith('Unable to compute test signature with JCA algorithm \'test\' using key {')
            assertTrue e.getMessage().endsWith('}: foo')
            assertSame ise, e.getCause()
        }
    }

    @Test
    void testVerifyFailsWithExternalException() {
        def pair = Jwts.SIG.RS256.keyPair().build()
        def ise = new IllegalStateException('foo')
        def alg = new TestAbstractSecureDigestAlgorithm() {
            @Override
            protected boolean doVerify(VerifySecureDigestRequest request) throws Exception {
                throw ise
            }
        }
        def data = 'foo'.getBytes(StandardCharsets.UTF_8)
        try {
            byte[] signature = alg.digest(new DefaultSecureRequest(data, null, null, pair.getPrivate()))
            alg.verify(new DefaultVerifySecureDigestRequest(data, null, null, pair.getPublic(), signature))
        } catch (SignatureException e) {
            assertTrue e.getMessage().startsWith('Unable to verify test signature with JCA algorithm \'test\' using key {')
            assertTrue e.getMessage().endsWith('}: foo')
            assertSame ise, e.getCause()
        }
    }

    class TestAbstractSecureDigestAlgorithm extends AbstractSecureDigestAlgorithm {

        TestAbstractSecureDigestAlgorithm() {
            super('test', 'test')
        }

        @Override
        protected void validateKey(Key key, boolean signing) {
        }

        @Override
        protected byte[] doDigest(SecureRequest request) throws Exception {
            return new byte[1]
        }

        @Override
        protected boolean doVerify(VerifySecureDigestRequest request) {
            return false
        }
    }
}
