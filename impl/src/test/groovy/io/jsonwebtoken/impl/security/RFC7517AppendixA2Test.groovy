/*
 * Copyright (C) 2020 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.Converters
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPrivateJwk
import org.junit.Test

import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateCrtKey

import static org.junit.Assert.*

/**
 * https://www.rfc-editor.org/rfc/rfc7517.html#appendix-A.2
 */
class RFC7517AppendixA2Test {

    private static final String ecEncode(int fieldSize, BigInteger coord) {
        return AbstractEcJwkFactory.toOctetString(fieldSize, coord)
    }

    private static final String rsaEncode(BigInteger i) {
        return Converters.BIGINT.applyTo(i) as String
    }

    private static final List<Map<String, String>> keys = [
            [
                    "kty": "EC",
                    "crv": "P-256",
                    "x"  : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y"  : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "d"  : "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
                    "use": "enc",
                    "kid": "1"
            ],
            [
                    "kty": "RSA",
                    "n"  : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
                            "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
                            "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
                            "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
                            "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
                            "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e"  : "AQAB",
                    "d"  : "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
                            "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
                            "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
                            "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
                            "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
                            "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
                    "p"  : "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
                            "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
                            "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
                    "q"  : "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
                            "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
                            "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
                    "dp" : "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
                            "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
                            "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
                    "dq" : "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
                            "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
                            "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
                    "qi" : "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
                            "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
                            "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
                    "alg": "RS256",
                    "kid": "2011-04-29"
            ]
    ]

    @Test
    void test() { // asserts we can parse and verify RFC values

        def m = keys[0]
        def jwk = Jwks.builder().add(m).build() as EcPrivateJwk
        def key = jwk.toKey()
        int fieldSize = key.params.curve.field.fieldSize
        assertTrue key instanceof ECPrivateKey
        assertEquals m.size(), jwk.size()
        assertEquals m.kty, jwk.getType()
        assertEquals m.crv, jwk.get('crv')
        assertEquals m.x, jwk.get('x')
        assertEquals m.x, ecEncode(fieldSize, jwk.toPublicJwk().toKey().w.affineX)
        assertEquals m.y, jwk.get('y')
        assertEquals m.y, ecEncode(fieldSize, jwk.toPublicJwk().toKey().w.affineY)
        assertEquals m.d, jwk.get('d').get()
        assertEquals m.d, ecEncode(fieldSize, key.s)
        assertEquals m.use, jwk.getPublicKeyUse()
        assertEquals m.kid, jwk.getId()

        m = keys[1]
        jwk = Jwks.builder().add(m).build() as RsaPrivateJwk
        key = jwk.toKey() as RSAPrivateCrtKey
        assertNotNull key
        assertEquals m.size(), jwk.size()
        assertEquals m.kty, jwk.getType()
        assertEquals m.n, jwk.get('n')
        assertEquals m.n, rsaEncode(key.modulus)
        assertEquals m.e, jwk.get('e')
        assertEquals m.e, rsaEncode(jwk.toPublicJwk().toKey().publicExponent)
        assertEquals m.d, jwk.get('d').get()
        assertEquals m.d, rsaEncode(key.privateExponent)
        assertEquals m.p, jwk.get('p').get()
        assertEquals m.p, rsaEncode(key.getPrimeP())
        assertEquals m.q, jwk.get('q').get()
        assertEquals m.q, rsaEncode(key.getPrimeQ())
        assertEquals m.dp, jwk.get('dp').get()
        assertEquals m.dp, rsaEncode(key.getPrimeExponentP())
        assertEquals m.dq, jwk.get('dq').get()
        assertEquals m.dq, rsaEncode(key.getPrimeExponentQ())
        assertEquals m.qi, jwk.get('qi').get()
        assertEquals m.qi, rsaEncode(key.getCrtCoefficient())
        assertEquals m.alg, jwk.getAlgorithm()
        assertEquals m.kid, jwk.getId()
    }
}
