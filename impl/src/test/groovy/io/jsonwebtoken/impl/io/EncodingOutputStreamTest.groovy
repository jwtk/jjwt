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

import io.jsonwebtoken.io.EncodingException
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class EncodingOutputStreamTest {

    @Test
    void testEncodingException() {
        def out = new ByteArrayOutputStream(128) {
            @Override
            synchronized void write(int b) {
                throw new IOException('foo')
            }
        }
        def wrapped = new EncodingOutputStream(out, 'base64url', 'payload')

        try {
            wrapped.write(1)
            fail()
        } catch (EncodingException expected) {
            String msg = 'Unable to base64url-encode payload: foo'
            assertEquals msg, expected.message
        }
    }
}
