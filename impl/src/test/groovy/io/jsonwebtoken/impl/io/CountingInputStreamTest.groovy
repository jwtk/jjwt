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

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.assertEquals

class CountingInputStreamTest {

    @Test
    void readEmpty() {
        def stream = new CountingInputStream(Streams.of(Bytes.EMPTY))
        stream.read()
        assertEquals 0, stream.getCount()
    }

    @Test
    void readSingle() {
        def single = (byte) 0x18 // any random byte is fine
        def data = new byte[1]; data[0] = single
        def stream = new CountingInputStream(Streams.of(data))
        assertEquals single, stream.read()
        assertEquals 1, stream.getCount()
    }

    @Test
    void testSkip() {
        def data = Strings.utf8('hello world')
        def stream = new CountingInputStream(Streams.of(data))
        stream.skip(6)
        assertEquals 6, stream.getCount()
        int w = ('w' as char)
        assertEquals w, stream.read()
    }
}
