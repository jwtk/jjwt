/*
 * Copyright (C) 2018 jsonwebtoken.io
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
package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPublicJwk
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicInteger

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultJweHeaderTest {

    private DefaultJweHeader header

    private static DefaultJweHeader h(Map<String, ?> m) {
        return new DefaultJweHeader(m)
    }

    @Test
    void testEncryptionAlgorithm() {
        assertEquals 'foo', h([enc: 'foo']).getEncryptionAlgorithm()
        assertEquals 'bar', h([enc: 'bar']).getEncryptionAlgorithm()
    }

    @Test
    void testGetName() {
        assertEquals 'JWE header', new DefaultJweHeader([:]).getName()
    }

    @Test
    void testEpkWithSecretJwk() {
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        try {
            h([epk: values])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {alg=HS256, kty=oct, k=<redacted>}. " +
                    "Value must be a Public JWK, not a Secret JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithPrivateJwk() {
        def jwk = Jwks.builder().key(TestKeys.ES256.pair.private as ECPrivateKey).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        try {
            h([epk: values])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {kty=EC, crv=P-256, " +
                    "x=ZWF7HQuzPoW_HarfomiU-HCMELJ486IzskTXL5fwuy4, y=Hf3WL_YAGj1XCSa5HSIAFsItY-SQNjRb1TdKQFEb3oU, " +
                    "d=<redacted>}. Value must be a Public JWK, not an EC Private JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithRsaPublicJwk() {
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public as RSAPublicKey).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        def epk = h([epk: values]).getEphemeralPublicKey()
        assertTrue epk instanceof RsaPublicJwk
        assertEquals(jwk, epk)
    }

    @Test
    void testEpkWithEcPublicJwkValues() {
        def jwk = Jwks.builder().key(TestKeys.ES256.pair.public as ECPublicKey).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        assertEquals jwk, h([epk: values]).get('epk')
    }

    @Test
    void testEpkWithInvalidEcPublicJwk() {
        def jwk = Jwks.builder().key(TestKeys.ES256.pair.public as ECPublicKey).build()
        def values = new LinkedHashMap(jwk) // copy params so we can mutate
        // We have a public JWK for a point on the curve, now swap out the x coordinate for something invalid:
        values.put('x', 'Kg')
        try {
            h([epk: values])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {kty=EC, crv=P-256, x=Kg, " +
                    "y=Hf3WL_YAGj1XCSa5HSIAFsItY-SQNjRb1TdKQFEb3oU}. EC JWK x,y coordinates do not exist on " +
                    "elliptic curve 'P-256'. This could be due simply to an incorrectly-created JWK or possibly an " +
                    "attempted Invalid Curve Attack (see https://safecurves.cr.yp.to/twist.html for more " +
                    "information)."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithEcPublicJwk() {
        def jwk = Jwks.builder().key(TestKeys.ES256.pair.public as ECPublicKey).build()
        header = h([epk: jwk])
        assertEquals jwk, header.get('epk')
        assertEquals jwk, header.getEphemeralPublicKey()
    }

    @Test
    void testEpkWithEdPublicJwk() {
        def keys = TestKeys.EdEC.collect({it -> it.pair.public as PublicKey})
        for(PublicKey key : keys) {
            def jwk = Jwks.builder().key((PublicKey)key as PublicKey).build()
            header = h([epk: jwk])
            assertEquals jwk, header.get('epk')
            assertEquals jwk, header.getEphemeralPublicKey()
        }
    }

    @Test
    void testAgreementPartyUInfo() {
        String val = "Party UInfo"
        byte[] info = val.getBytes(StandardCharsets.UTF_8)
        assertArrayEquals info, h([apu: info]).getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyUInfoString() {
        String val = "Party UInfo"
        byte[] info = val.getBytes(StandardCharsets.UTF_8)
        assertArrayEquals info, h([apu: info]).getAgreementPartyUInfo()
    }

    @Test
    void testEmptyAgreementPartyUInfo() {
        byte[] info = new byte[0]
        assertNull h([apu: info]).getAgreementPartyUInfo()
    }

    @Test
    void testEmptyAgreementPartyUInfoString() {
        def val = '    '
        assertNull h([apu: val]).getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyVInfo() {
        String val = "Party VInfo"
        byte[] info = Strings.utf8(val)
        assertArrayEquals info, h([apv: info]).getAgreementPartyVInfo()
    }

    @Test
    void testAgreementPartyVInfoString() {
        String val = "Party VInfo"
        byte[] info = Strings.utf8(val)
        assertArrayEquals info, h(apv: info).getAgreementPartyVInfo()
    }

    @Test
    void testEmptyAgreementPartyVInfo() {
        byte[] info = new byte[0]
        assertNull h([apv: info]).getAgreementPartyVInfo()
    }

    @Test
    void testEmptyAgreementPartyVInfoString() {
        String s = '  '
        header = h([apv: s])
        assertNull header.getAgreementPartyVInfo()
    }

    @Test
    void testIv() {
        byte[] bytes = new byte[12]
        Randoms.secureRandom().nextBytes(bytes)
        header = h([iv: bytes])
        assertEquals Encoders.BASE64URL.encode(bytes), header.get('iv')
        assertTrue MessageDigest.isEqual(bytes, header.getInitializationVector())
    }

    @Test
    void testIvWithIncorrectSize() {
        byte[] bytes = new byte[7]
        Randoms.secureRandom().nextBytes(bytes)
        try {
            h([iv: bytes])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'iv' (Initialization Vector) value. " +
                    "Byte array must be exactly 96 bits (12 bytes). Found 56 bits (7 bytes)"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testTag() {
        byte[] bytes = new byte[16]
        Randoms.secureRandom().nextBytes(bytes)
        header = h([tag: bytes])
        assertEquals Encoders.BASE64URL.encode(bytes), header.get('tag')
        assertTrue MessageDigest.isEqual(bytes, header.getAuthenticationTag())
    }

    @Test
    void testTagWithIncorrectSize() {
        byte[] bytes = new byte[15]
        Randoms.secureRandom().nextBytes(bytes)
        try {
            h([tag: bytes])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'tag' (Authentication Tag) value. " +
                    "Byte array must be exactly 128 bits (16 bytes). Found 120 bits (15 bytes)"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cByte() {
        header = h([p2c: Byte.MAX_VALUE])
        assertEquals 127, header.getPbes2Count()
    }

    @Test
    void testP2cShort() {
        header = h([p2c: Short.MAX_VALUE])
        assertEquals 32767, header.getPbes2Count()
    }

    @Test
    void testP2cInt() {
        header = h([p2c: Integer.MAX_VALUE])
        assertEquals 0x7fffffff as Integer, header.getPbes2Count()
    }

    @Test
    void testP2cAtomicInteger() {
        header = h([p2c: new AtomicInteger(Integer.MAX_VALUE)])
        assertEquals 0x7fffffff as Integer, header.getPbes2Count()
    }

    @Test
    void testP2cString() {
        header = h([p2c: '100'])
        assertEquals 100, header.getPbes2Count()
    }

    @Test
    void testP2cZero() {
        try {
            h([p2c: 0])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: 0. Value must be a positive integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cNegative() {
        try {
            h([p2c: -1])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: -1. Value must be a positive integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cTooLarge() {
        try {
            h([p2c: Long.MAX_VALUE])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: 9223372036854775807. " +
                    "Value cannot be represented as a java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cDecimal() {
        double d = 42.2348423d
        try {
            h([p2c: d])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: $d. " +
                    "Value cannot be represented as a java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testPbe2SaltBytes() {
        byte[] salt = new byte[32]
        Randoms.secureRandom().nextBytes(salt)
        header = h([p2s: salt])
        assertEquals Encoders.BASE64URL.encode(salt), header.get('p2s')
        assertArrayEquals salt, header.getPbes2Salt()
    }

    @Test
    void pbe2SaltStringTest() {
        byte[] salt = new byte[32]
        Randoms.secureRandom().nextBytes(salt)
        String val = Encoders.BASE64URL.encode(salt)
        header = h([p2s: val])
        //ensure that even though a Base64Url string was set, we get back a byte[]:
        assertArrayEquals salt, header.getPbes2Salt()
    }

    @Test
    void testPbe2SaltInputTooSmall() {
        byte[] salt = new byte[7] // RFC requires a minimum of 64 bits (8 bytes), so we go 1 byte less
        Randoms.secureRandom().nextBytes(salt)
        String val = Encoders.BASE64URL.encode(salt)
        try {
            h([p2s: val])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2s' (PBES2 Salt Input) value: $val. " +
                    "Byte array must be at least 64 bits (8 bytes). Found 56 bits (7 bytes)"
            assertEquals msg, expected.getMessage()
        }
    }
}
