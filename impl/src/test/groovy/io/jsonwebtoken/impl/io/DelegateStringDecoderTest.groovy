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

import io.jsonwebtoken.io.Decoder
import io.jsonwebtoken.io.DecodingException
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.*

@SuppressWarnings('GrDeprecatedAPIUsage')
class DelegateStringDecoderTest {

    @Test
    void decode() {
        def value = 'test'
        def test = new Decoder<String,byte[]>() {
            @Override
            byte[] decode(String s) throws DecodingException {
                return Strings.utf8(value);
            }
            @Override
            InputStream wrap(InputStream inputStream) {
                return null
            }
        }
        def d = new DelegateStringDecoder(test)
        assertArrayEquals Strings.utf8(value), d.decode(value)
    }

    @Test
    void wrap() {
        def value = 'test'
        boolean invoked = false
        def stream = new ByteArrayInputStream(Strings.utf8(value))
        def test = new Decoder<String,byte[]>() {
            @Override
            byte[] decode(String s) throws DecodingException {
                return Strings.utf8(value);
            }
            @Override
            InputStream wrap(InputStream inputStream) {
                invoked = true
                stream
            }
        }
        def d = new DelegateStringDecoder(test)
        assertSame stream, d.wrap(stream)
        assertTrue invoked
    }
}
