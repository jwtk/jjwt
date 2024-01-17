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

import io.jsonwebtoken.impl.DefaultJwtParser
import io.jsonwebtoken.impl.RfcTests
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Serializer
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class RFC7515AppendixETest {

    static final Serializer<Map<String, ?>> serializer = Services.get(Serializer)
    static final Deserializer<Map<String, ?>> deserializer = Services.get(Deserializer)

    static byte[] ser(def value) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512)
        serializer.serialize(value, baos)
        return baos.toByteArray()
    }

    static <T> T deser(String s) {
        T t = deserializer.deserialize(Streams.reader(s)) as T
        return t
    }

    @Test
    void test() {

        String headerString = RfcTests.stripws('''
        {"alg":"none",
         "crit":["http://example.invalid/UNDEFINED"],
         "http://example.invalid/UNDEFINED":true
        }''')
        Map<String, ?> header = deser(headerString)
        String b64url = Encoders.BASE64URL.encode(ser(header))

        String jws = b64url + '.RkFJTA.'

        try {
            Jwts.parser().unsecured().build().parse(jws)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = String.format(DefaultJwtParser.CRIT_UNSECURED_MSG, header)
            assertEquals msg, expected.getMessage()
        }
    }


    @Test
    void testProtected() {

        // The RFC test case above shows an Unprotected header using the 'crit' header, but this isn't allowed per
        // their own language in https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11.  To assert that
        // the invalid crit values can't be used in Protected headers either, we amend the above test to represent
        // that scenario as well:

        // 'alg' here indicates a protected header, so we should get a different exception message compared to
        // the test above
        String critVal = 'http://example.invalid/UNDEFINED'
        String headerString = RfcTests.stripws("""
        {"alg":"HS256",
         "crit":["$critVal"],
         "$critVal":true
        }""")
        Map<String, ?> header = deser(headerString)
        String b64url = Encoders.BASE64URL.encode(ser(header))

        String jws = b64url + '.RkFJTA.fakesignature' // needed to parse a JWS properly

        try {
            Jwts.parser().unsecured().build().parse(jws)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = String.format(DefaultJwtParser.CRIT_UNSUPPORTED_MSG, critVal, critVal, header)
            assertEquals msg, expected.getMessage()
        }
    }
}
