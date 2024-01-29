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
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.*
import org.junit.Test

import static org.junit.Assert.*

/**
 * The {@link SecretJwkFactory} is tested in other classes (JwksTest, JwkParserTest, etc) - this class exists
 * primarily to fill in coverage gaps where necessary.
 *
 * @since 0.12.0
 */
class SecretJwkFactoryTest {

    private static Set<MacAlgorithm> macAlgs() {
        return Jwts.SIG.get().values().findAll({ it -> it instanceof MacAlgorithm }) as Collection<MacAlgorithm>
    }

    @Test
    // if a jwk does not have an 'alg' or 'use' param, we default to an AES key
    void testNoAlgNoSigJcaName() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA256).build()
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
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA256).build()
        SecretJwk result = Jwks.builder().add(jwk).operations().add(Jwks.OP.SIGN).and().build() as SecretJwk
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
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA384).build()
        SecretJwk result = Jwks.builder().add(jwk).operations().add(Jwks.OP.SIGN).and().build() as SecretJwk
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
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA512).build()
        SecretJwk result = Jwks.builder().add(jwk).operations().add(Jwks.OP.SIGN).and().build() as SecretJwk
        assertNull result.getAlgorithm()
        assertNull result.get('use')
        assertEquals 'HmacSHA512', result.toKey().getAlgorithm()
    }

    @Test
    // no 'alg' jwk property, but 'use' is 'sig', so forces jcaName to be HmacSHA256
    void testNoAlgAndSigUseForHS256() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA256).build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'sig').build() as SecretJwk
        assertEquals 'HmacSHA256', result.toKey().getAlgorithm() // jcaName has been changed to a sig algorithm
    }

    @Test
    // no 'alg' jwk property, but 'use' is 'sig', so forces jcaName to be HmacSHA384
    void testNoAlgAndSigUseForHS384() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA384).build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'sig').build() as SecretJwk
        assertEquals 'HmacSHA384', result.toKey().getAlgorithm()
    }

    @Test
    // no 'alg' jwk property, but 'use' is 'sig', so forces jcaName to be HmacSHA512
    void testNoAlgAndSigUseForHS512() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA512).build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'sig').build() as SecretJwk
        assertEquals 'HmacSHA512', result.toKey().getAlgorithm()
    }

    @Test
    // no 'alg' jwk property, but 'use' is something other than 'sig', so jcaName should default to AES
    void testNoAlgAndNonSigUse() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.NA256).build()
        assertFalse jwk.containsKey('alg')
        assertFalse jwk.containsKey('use')
        SecretJwk result = Jwks.builder().add(jwk).add('use', 'foo').build() as SecretJwk
        assertEquals 'AES', result.toKey().getAlgorithm()
    }

    /**
     * @since 0.12.4
     */
    @Test
    // 'oct' type, but 'alg' value is not a secret key algorithm (and therefore malformed)
    void testMismatchedAlgorithm() {
        try {
            Jwks.builder().key(TestKeys.NA256).add('alg', Jwts.SIG.RS256.getId()).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Invalid Secret JWK ${AbstractJwk.ALG} value 'RS256'. Secret JWKs may only be used with " +
                    "symmetric (secret) key algorithms."
            assertEquals msg, expected.message
        }
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
        } catch (WeakKeyException expected) {
            String msg = "Secret JWK 'alg' (Algorithm) value is 'HS384', but the 'k' (Key Value) length is smaller " +
                    "than the HS384 minimum length of 384 bits (48 bytes) required by " +
                    "[JWA RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2), 2nd " +
                    "paragraph: 'A key of the same size as the hash output or larger MUST be used with this " +
                    "algorithm.'"
            assertEquals msg, expected.getMessage()
        }
    }

    /**
     * Test when a {@code k} size is smaller, equal to, and larger than the minimum required number of bits/bytes for
     * a given HmacSHA* algorithm. The RFCs indicate smaller-than is not allowed, while equal-to and greater-than are
     * allowed.
     *
     * This test asserts this allowed behavior per https://github.com/jwtk/jjwt/issues/905
     * @see <a href="https://github.com/jwtk/jjwt/issues/905">JJWT Issue 905</a>
     * @since 0.12.4
     */
    @Test
    void testAllowedKeyLengths() {

        def parser = Jwks.parser().build()

        for (MacAlgorithm alg : macAlgs()) {

            // 3 key length sizes for each alg to test:
            // index 0: smaller than minimum required
            // index 1: minimum required
            // index 2: more than minimum required:
            def sizes = [alg.keyBitLength - Byte.SIZE, alg.keyBitLength, alg.keyBitLength + Byte.SIZE]

            for (int i = 0; i < sizes.size(); i++) {

                def kBitLength = sizes.get(i)
                def k = Bytes.random(Bytes.length(kBitLength))

                def jwkJson = """
                {
                  "kid": "${UUID.randomUUID().toString()}",
                  "kty": "oct",
                  "alg": "${alg.getId()}",
                  "k": "${Encoders.BASE64URL.encode(k)}"
                }""".toString()

                def jwk
                try {
                    jwk = parser.parse(jwkJson)
                } catch (WeakKeyException expected) {
                    assertEquals("Should only occur on index 0 with less-than-minimum key length", 0, i)
                    String msg = "Secret JWK 'alg' (Algorithm) value is '${alg.getId()}', but the 'k' (Key Value) " +
                            "length is smaller than the ${alg.getId()} minimum length of " +
                            "${Bytes.bitsMsg(alg.keyBitLength)} required by " +
                            "[JWA RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2), " +
                            "2nd paragraph: 'A key of the same size as the hash output or larger MUST be used with " +
                            "this algorithm.'"
                    assertEquals msg, expected.getMessage()
                    continue // expected for index 0 (purposefully weak key), so let loop continue
                }

                // otherwise not weak, sizes should reflect equal-to or greater-than alg bitlength sizes
                assert jwk instanceof SecretJwk
                assertEquals alg.getId(), jwk.getAlgorithm()
                def bytes = jwk.toKey().getEncoded()
                assertTrue Bytes.bitLength(bytes) >= alg.keyBitLength
                assertEquals Bytes.length(kBitLength), jwk.toKey().getEncoded().length
            }
        }
    }
}
