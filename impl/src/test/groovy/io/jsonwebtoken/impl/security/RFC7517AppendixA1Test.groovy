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

import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPublicJwk
import org.junit.Test

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

/**
 * https://www.rfc-editor.org/rfc/rfc7517.html#appendix-A.1
 */
class RFC7517AppendixA1Test {

    private static final List<Map<String, String>> keys = [
            [
                    "kty": "EC",
                    "crv": "P-256",
                    "x"  : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y"  : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use": "enc",
                    "kid": "1"
            ],
            [
                    "kty": "RSA",
                    "n"  : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                            "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                            "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                            "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                            "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                            "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" as String,
                    "e"  : "AQAB",
                    "alg": "RS256",
                    "kid": "2011-04-29"
            ]
    ]

    @Test
    void test() { // asserts we can parse and verify RFC values

        def m = keys[0]
        EcPublicJwk ecPubJwk = Jwks.builder().add(m).build() as EcPublicJwk
        assertTrue ecPubJwk.toKey() instanceof ECPublicKey
        assertEquals m.size(), ecPubJwk.size()
        assertEquals m.kty, ecPubJwk.getType()
        assertEquals m.crv, ecPubJwk.get('crv')
        assertEquals m.x, ecPubJwk.get('x')
        assertEquals m.y, ecPubJwk.get('y')
        assertEquals m.use, ecPubJwk.getPublicKeyUse()
        assertEquals m.kid, ecPubJwk.getId()

        m = keys[1]
        RsaPublicJwk rsaPublicJwk = Jwks.builder().add(m).build() as RsaPublicJwk
        assertTrue rsaPublicJwk.toKey() instanceof RSAPublicKey
        assertEquals m.size(), rsaPublicJwk.size()
        assertEquals m.kty, rsaPublicJwk.getType()
        assertEquals m.n, rsaPublicJwk.get('n')
        assertEquals m.e, rsaPublicJwk.get('e')
        assertEquals m.alg, rsaPublicJwk.getAlgorithm()
        assertEquals m.kid, rsaPublicJwk.getId()
    }

}
