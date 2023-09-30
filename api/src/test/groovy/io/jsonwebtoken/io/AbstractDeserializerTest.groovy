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
package io.jsonwebtoken.io

import org.junit.Test

import static org.junit.Assert.*

class AbstractDeserializerTest {

    @Test
    void deserializeNullByteArray() {
        boolean invoked = false
        def deser = new AbstractDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                assertEquals EOF, reader.read()
                invoked = true
            }
        }
        deser.deserialize((byte[]) null)
        assertTrue invoked
    }

    @Test
    void deserializeEmptyByteArray() {
        boolean invoked = false
        def deser = new AbstractDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                assertEquals EOF, reader.read()
                invoked = true
            }
        }
        deser.deserialize(new byte[0])
        assertTrue invoked
    }

    @Test
    void deserializeByteArray() {
        byte b = 0x01
        def bytes = new byte[1]
        bytes[0] = b
        def des = new AbstractDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                assertEquals b, reader.read()
                return 42
            }
        }
        assertEquals 42, des.deserialize(bytes)
    }

    @Test
    void deserializeException() {

        def ex = new RuntimeException('foo')
        def des = new AbstractDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                throw ex
            }
        }

        try {
            des.deserialize(new byte[0])
        } catch (DeserializationException expected) {
            String msg = 'Unable to deserialize: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }
}
