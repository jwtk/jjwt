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

import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import io.jsonwebtoken.security.SecretJwk
import org.junit.Test

import static org.junit.Assert.*

/**
 * The {@link SecretJwkFactory} is tested in other classes (JwksTest, JwkParserTest, etc) - this class exists
 * primarily to fill in coverage gaps where necessary.
 *
 * @since JJWT_RELEASE_VERSION
 */
class SecretJwkFactoryTest {

    @Test
    // if a jwk does not have an 'alg' or 'use' param, we default to an AES key
    void testNoAlgNoSigJcaName() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).delete('alg').build()
        SecretJwk result = Jwks.builder().add(jwk).build() as SecretJwk
        assertEquals 'AES', result.toKey().getAlgorithm()
    }

    @Test
    void testJwkHS256AlgSetsKeyJcaNameCorrectly() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).build()
        SecretJwk result = Jwks.builder().add(jwk).build() as SecretJwk
        assertEquals 'HmacSHA256', result.toKey().getAlgorithm()
    }

    @Test
    void testSignOpSetsKeyHmacSHA256() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).delete('alg').build()
        SecretJwk result = Jwks.builder().add(jwk).operations([Jwks.OP.SIGN]).build() as SecretJwk
        assertNull result.getAlgorithm()
        assertNull result.get('use')
        assertEquals 'HmacSHA256', result.toKey().getAlgorithm()
    }

    @Test
    void testJwkHS384AlgSetsKeyJcaNameCorrectly() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS384).build()
        SecretJwk result = Jwks.builder().add(jwk).build() as SecretJwk
        assertEquals 'HmacSHA384', result.toKey().getAlgorithm()
    }

    @Test
    void testSignOpSetsKeyHmacSHA384() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS384).delete('alg').build()
        SecretJwk result = Jwks.builder().add(jwk).operations([Jwks.OP.SIGN]).build() as SecretJwk
        assertNull result.getAlgorithm()
        assertNull result.get('use')
        assertEquals 'HmacSHA384', result.toKey().getAlgorithm()
    }

    @Test
    void testJwkHS512AlgSetsKeyJcaNameCorrectly() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS512).build()
        SecretJwk result = Jwks.builder().add(jwk).build() as SecretJwk
        assertEquals 'HmacSHA512', result.toKey().getAlgorithm()
    }

    @Test
    void testSignOpSetsKeyHmacSHA512() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS512).delete('alg').build()
        SecretJwk result = Jwks.builder().add(jwk).operations([Jwks.OP.SIGN]).build() as SecretJwk
        assertNull result.getAlgorithm()
        assertNull result.get('use')
        assertEquals 'HmacSHA512', result.toKey().getAlgorithm()
    }

    @Test
    // no 'alg' jwk property, but 'use' is 'sig', so forces jcaName to be HmacSHA256
    void testNoAlgAndSigUseForHS256() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).delete('alg').build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'sig').build() as SecretJwk
        assertEquals 'HmacSHA256', result.toKey().getAlgorithm() // jcaName has been changed to a sig algorithm
    }

    @Test
    // no 'alg' jwk property, but 'use' is 'sig', so forces jcaName to be HmacSHA384
    void testNoAlgAndSigUseForHS384() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS384).delete('alg').build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'sig').build() as SecretJwk
        assertEquals 'HmacSHA384', result.toKey().getAlgorithm()
    }

    @Test
    // no 'alg' jwk property, but 'use' is 'sig', so forces jcaName to be HmacSHA512
    void testNoAlgAndSigUseForHS512() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS512).delete('alg').build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'sig').build() as SecretJwk
        assertEquals 'HmacSHA512', result.toKey().getAlgorithm()
    }

    @Test
    // no 'alg' jwk property, but 'use' is something other than 'sig', so jcaName should default to AES
    void testNoAlgAndNonSigUse() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).delete('alg').build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'foo').build() as SecretJwk
        assertEquals 'AES', result.toKey().getAlgorithm()
    }

    /**
     * Test the case where a jwk `alg` value is present, but the key material doesn't match that algs key length
     * requirements.  This would be a malformed key.
     */
    @Test
    void testSizeMismatchedSecretJwk() {

        //first get a valid HS256 JWK:
        SecretJwk validJwk = Jwks.builder().key(TestKeys.HS256).build()

        //now associate it with an alg identifier that is more than the key is capable of:
        try {
            Jwks.builder().add(validJwk)
                    .add('alg', 'HS384')
                    .build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Secret JWK 'alg' (Algorithm) value is 'HS384', but the 'k' (Key Value) length does " +
                    "not equal the 'HS384' length requirement of 384 bits (48 bytes). This discrepancy could " +
                    "be the result of an algorithm substitution attack or simply an erroneously constructed " +
                    "JWK. In either case, it is likely to result in unexpected or undesired security consequences."
            assertEquals msg, expected.getMessage()
        }
    }
}
