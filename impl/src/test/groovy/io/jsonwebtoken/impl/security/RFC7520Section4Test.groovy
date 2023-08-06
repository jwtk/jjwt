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
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPrivateJwk
import io.jsonwebtoken.security.SecretJwk
import org.junit.Test

import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class RFC7520Section4Test {

    static final byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8)
    }

    static final String utf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8)
    }

    static final String b64Url(byte[] bytes) {
        return Encoders.BASE64URL.encode(bytes)
    }

    static final byte[] b64Url(String s) {
        return Decoders.BASE64URL.decode(s)
    }

    static final String FIGURE_7 =
            "It\u2019s a dangerous business, Frodo, going out your " +
                    "door. You step onto the road, and if you don't keep your feet, " +
                    "there\u2019s no knowing where you might be swept off " +
                    "to."

    static final String FIGURE_8 = Strings.trimAllWhitespace('''
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4
    ''')

    static final String FIGURE_9 = Strings.trimAllWhitespace('''
    {
      "alg": "RS256",
      "kid": "bilbo.baggins@hobbiton.example"
    }
    ''')

    static final String FIGURE_10 = Strings.trimAllWhitespace('''
    eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX
    hhbXBsZSJ9
    ''')

    static final String FIGURE_13 = Strings.trimAllWhitespace('''
    eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX
    hhbXBsZSJ9
    .
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4
    .
    MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK
    ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J
    IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w
    W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP
    xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f
    cIe8u9ipH84ogoree7vjbU5y18kDquDg
    ''')

    static final String FIGURE_16 = Strings.trimAllWhitespace('''
    {
      "alg": "PS384",
      "kid": "bilbo.baggins@hobbiton.example"
    }
    ''')

    static final String FIGURE_17 = Strings.trimAllWhitespace('''
    eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX
    hhbXBsZSJ9
    ''')

    static final String FIGURE_20 = Strings.trimAllWhitespace('''
    eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX
    hhbXBsZSJ9
    .
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4
    .
    cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I
    pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU
    vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX
    e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT
    0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a
    6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw
    ''')

    static final String FIGURE_23 = Strings.trimAllWhitespace('''
    {
      "alg": "ES512",
      "kid": "bilbo.baggins@hobbiton.example"
    }
    ''')

    static final String FIGURE_24 = Strings.trimAllWhitespace('''
    eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX
    hhbXBsZSJ9
    ''')

    static final String FIGURE_27 = Strings.trimAllWhitespace('''
    eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX
    hhbXBsZSJ9
    .
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4
    .
    AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb
    u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv
    AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2
    ''')

    static final String FIGURE_30 = Strings.trimAllWhitespace('''
    {
      "alg": "HS256",
      "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
    }
    ''')

    static final String FIGURE_31 = Strings.trimAllWhitespace('''
    eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW
    VlZjMxNGJjNzAzNyJ9
    ''')

    static final String FIGURE_34 = Strings.trimAllWhitespace('''
    eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW
    VlZjMxNGJjNzAzNyJ9
    .
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4
    .
    s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0
    ''')

    static final String FIGURE_37 = FIGURE_30 // same in RFC
    static final String FIGURE_38 = FIGURE_31 // same in RFC
    static final String FIGURE_41 = Strings.trimAllWhitespace('''
    eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW
    VlZjMxNGJjNzAzNyJ9
    .
    .
    s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0
    ''')


    static {
        //ensure our representations match the RFC:
        assert FIGURE_7.equals(utf8(b64Url(FIGURE_8)))
        assert FIGURE_10.equals(b64Url(utf8(FIGURE_9)))
        assert FIGURE_17.equals(b64Url(utf8(FIGURE_16)))
        assert FIGURE_24.equals(b64Url(utf8(FIGURE_23)))
        assert FIGURE_31.equals(b64Url(utf8(FIGURE_30)))
        assert FIGURE_38.equals(b64Url(utf8(FIGURE_37)))
    }

    @Test
    void testSection4_1() {

        RsaPrivateJwk jwk = Jwks.parser().build().parse(RFC7520Section3Test.FIGURE_4) as RsaPrivateJwk
        RSAPrivateKey key = jwk.toKey()

        def alg = Jwts.SIG.RS256

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 2, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_9)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_7)
                .signWith(key, alg)
                .compact()

        assertEquals FIGURE_13, result

        // Assert round trip works as expected:
        def parsed = Jwts.parser().verifyWith(jwk.toPublicJwk().toKey()).build().parseContentJws(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals FIGURE_7, utf8(parsed.payload)
    }

    @Test
    void testSection4_2() {

        RsaPrivateJwk jwk = Jwks.parser().build().parse(RFC7520Section3Test.FIGURE_4) as RsaPrivateJwk
        RSAPrivateKey key = jwk.toKey()

        def alg = Jwts.SIG.PS384
        String kid = 'bilbo.baggins@hobbiton.example'

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 2, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals kid, m.get('kid')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_16)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(kid).and()
                .setPayload(FIGURE_7)
                .signWith(key, alg)
                .compact()


        // As reminded in https://www.rfc-editor.org/rfc/rfc7520.html#section-4.2, it is not possible to
        // generate the same exact signature because RSASSA-PSS uses random data during signature creation
        // so we at least assert that our result starts with the RFC value, ignoring the final signature
        assertTrue result.startsWith(FIGURE_20.substring(0, FIGURE_20.lastIndexOf('.')))

        // even though we can't know what the signature output is ahead of time due to random data, we can assert
        // the signature to guarantee a round trip works as expected:
        def parsed = Jwts.parser()
                .verifyWith(jwk.toPublicJwk().toKey())
                .build().parseContentJws(result)

        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals kid, parsed.header.getKeyId()
        assertEquals FIGURE_7, utf8(parsed.payload)
    }

    @Test
    void testSection4_3() {

        EcPrivateJwk jwk = Jwks.parser().build().parse(RFC7520Section3Test.FIGURE_2) as EcPrivateJwk
        ECPrivateKey key = jwk.toKey()

        def alg = Jwts.SIG.ES512

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 2, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_23)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_7)
                .signWith(key, alg)
                .compact()

        // As reminded in https://www.rfc-editor.org/rfc/rfc7520.html#section-4.3, it is not possible to
        // generate the same exact signature because RSASSA-PSS uses random data during signature creation
        // so we at least assert that our result starts with the RFC value, ignoring the final signature
        assertTrue result.startsWith(FIGURE_27.substring(0, FIGURE_27.lastIndexOf('.')))

        // even though we can't know what the signature output is ahead of time due to random data, we can assert
        // the signature to guarantee a round trip works as expected:
        def parsed = Jwts.parser()
                .verifyWith(jwk.toPublicJwk().toKey())
                .build().parseContentJws(result)

        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals FIGURE_7, utf8(parsed.payload)
    }

    @Test
    void testSection4_4() {

        SecretJwk jwk = Jwks.parser().build().parse(RFC7520Section3Test.FIGURE_5) as SecretJwk
        SecretKey key = jwk.toKey()

        def alg = Jwts.SIG.HS256

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 2, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_30)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_7)
                .signWith(key, alg)
                .compact()

        assertEquals FIGURE_34, result

        // Assert round trip works as expected:
        def parsed = Jwts.parser().verifyWith(key).build().parseContentJws(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals FIGURE_7, utf8(parsed.payload)
    }

    @Test
    void testSection4_5() {

        SecretJwk jwk = Jwks.parser().build().parse(RFC7520Section3Test.FIGURE_5) as SecretJwk
        SecretKey key = jwk.toKey()

        def alg = Jwts.SIG.HS256

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 2, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_37)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_7)
                .signWith(key, alg)
                .compact()

        String detached = result.substring(0, result.indexOf('.')) + '..' +
                result.substring(result.lastIndexOf('.') + 1, result.length())

        assertEquals FIGURE_41, detached

        // Assert round trip works as expected:
        def parsed = Jwts.parser().verifyWith(key).build().parseContentJws(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals FIGURE_7, utf8(parsed.payload)
    }

    // void testSection4_6() {}  we don't support non-compact JSON serialization yet
    // void testSection4_7() {}  we don't support non-compact JSON serialization yet
    // void testSection4_8() {}  we don't support non-compact JSON serialization yet
}
