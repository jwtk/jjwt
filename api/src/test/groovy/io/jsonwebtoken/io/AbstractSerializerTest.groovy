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

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class AbstractSerializerTest {

    @Test
    void serializeByteArray() {
        def value = 42
        def ser = new AbstractSerializer() {
            @Override
            protected void doSerialize(Object o, OutputStream out) throws Exception {
                assertEquals value, o
                out.write(0x01)
            }
        }

        def out = ser.serialize(value)
        assertEquals 0x01, out[0]
    }

    @Test
    void serializeException() {

        def ex = new RuntimeException('foo')
        def ser = new AbstractSerializer() {
            @Override
            protected void doSerialize(Object o, OutputStream out) throws Exception {
                throw ex
            }
        }

        try {
            ser.serialize(42, new ByteArrayOutputStream())
        } catch (SerializationException expected) {
            String msg = 'Unable to serialize object of type java.lang.Integer: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }
}
