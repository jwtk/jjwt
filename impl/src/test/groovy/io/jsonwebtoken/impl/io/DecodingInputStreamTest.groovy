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
package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.DecodingException
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class DecodingInputStreamTest {

    @Test
    void decodingException() {
        def ins = new ByteArrayInputStream(Strings.utf8('test')) {
            @Override
            synchronized int read() {
                throw new IOException("foo")
            }
        }

        def decoding = new DecodingInputStream(ins, 'base64url', 'payload')

        try {
            decoding.read()
            fail()
        } catch (DecodingException expected) {
            String msg = 'Unable to base64url-decode payload: foo'
            assertEquals msg, expected.message
        }
    }
}
