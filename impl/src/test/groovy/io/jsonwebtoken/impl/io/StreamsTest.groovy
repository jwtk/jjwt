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
import org.junit.Test

import java.util.concurrent.Callable

import static org.junit.Assert.*

class StreamsTest {

    @Test
    void runWrapsExceptionAsRuntimeIOException() {
        def ex = new RuntimeException('foo')
        def c = new Callable() {
            @Override
            Object call() throws Exception {
                throw ex
            }
        }
        try {
            Streams.run(c, 'bar')
            fail()
        } catch (io.jsonwebtoken.io.IOException expected) {
            String msg = 'IO failure: bar. Cause: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }

    @Test
    void runWrapsExceptionAsRuntimeIOExceptionWithPunctuation() {
        def ex = new RuntimeException('foo')
        def c = new Callable() {
            @Override
            Object call() throws Exception {
                throw ex
            }
        }
        try {
            Streams.run(c, 'bar.') // period at the end, don't add another
            fail()
        } catch (io.jsonwebtoken.io.IOException expected) {
            String msg = 'IO failure: bar. Cause: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }

    @Test
    void streamFromNullByteArray() {
        def stream = Streams.of((byte[]) null)
        assertNotNull stream
        assertEquals 0, stream.available()
        assertEquals(-1, stream.read())
    }

    @Test
    void streamWithEmptyByteArray() {
        def stream = Streams.of(Bytes.EMPTY)
        assertNotNull stream
        assertEquals 0, stream.available()
        assertEquals(-1, stream.read())
    }
}
