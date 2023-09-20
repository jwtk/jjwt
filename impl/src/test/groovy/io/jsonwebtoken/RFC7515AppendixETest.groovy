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
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Reader
import io.jsonwebtoken.io.Writer
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class RFC7515AppendixETest {

    static final writer = Services.loadFirst(Writer) as Writer<Map<String, ?>>
    static final reader = Services.loadFirst(Reader) as Reader<Map<String, ?>>

    static byte[] ser(Writer writer, def value) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512)
        OutputStreamWriter w = new OutputStreamWriter(baos, StandardCharsets.UTF_8)
        writer.write(w, value)
        w.close()
        return baos.toByteArray()
    }

    @Test
    void test() {

        String headerString = RfcTests.stripws('''
        {"alg":"none",
         "crit":["http://example.invalid/UNDEFINED"],
         "http://example.invalid/UNDEFINED":true
        }''')
        Map<String, ?> header = reader.read(new StringReader(headerString))
        String b64url = Encoders.BASE64URL.encode(ser(writer, header))

        String jws = b64url + '.RkFJTA.'

        try {
            Jwts.parser().enableUnsecured().build().parse(jws)
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
        Map<String, ?> header = reader.read(new StringReader(headerString))
        String b64url = Encoders.BASE64URL.encode(ser(writer, header))

        String jws = b64url + '.RkFJTA.fakesignature' // needed to parse a JWS properly

        try {
            Jwts.parser().enableUnsecured().build().parse(jws)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = String.format(DefaultJwtParser.CRIT_UNSUPPORTED_MSG, critVal, critVal, header)
            assertEquals msg, expected.getMessage()
        }
    }
}
