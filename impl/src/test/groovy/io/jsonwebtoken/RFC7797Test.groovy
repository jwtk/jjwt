/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken

import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.*

/**
 * Test cases for https://datatracker.ietf.org/doc/html/rfc7797 functionality.
 */
class RFC7797Test {


    @Test
    void testJwtDisabledEncoding() {
        try {
            Jwts.builder().content('hello').encryptWith(TestKeys.A128GCM, Jwts.ENC.A128GCM)
                    .encodePayload(false) // not allowed with JWE
                    .compact()
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Payload encoding may not be disabled for JWEs, only JWSs.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testUnprotectedJwtDisabledEncoding() {
        try {
            Jwts.builder().content('hello')
                    .encodePayload(false) // not allowed with JWT
                    .compact()
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Payload encoding may not be disabled for unprotected JWTs, only JWSs.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwsDisabledEncodingWithBytesPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id)
                .build().parseContentJws(s, payload)

        assertArrayEquals payload, jws.getPayload()
    }
}
