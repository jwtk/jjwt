/*
 * Copyright (C) 2014 jsonwebtoken.io
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
//file:noinspection GrDeprecatedAPIUsage
package io.jsonwebtoken.gson.io

import com.google.gson.Gson
import com.google.gson.JsonIOException
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class GsonDeserializerTest {

    private GsonDeserializer deserializer

    private def deser(byte[] data) {
        def ins = new ByteArrayInputStream(data)
        def reader = new InputStreamReader(ins, Strings.UTF_8)
        deserializer.deserialize(reader)
    }

    private def deser(String s) {
        return deser(Strings.utf8(s))
    }

    @Before
    void setUp() {
        deserializer = new GsonDeserializer()
    }

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assertTrue deserializer instanceof GsonDeserializer
    }

    @Test
    void testDefaultConstructor() {
        assertNotNull deserializer.gson
    }

    @Test
    void testGsonConstructor() {
        def customGSON = new Gson()
        deserializer = new GsonDeserializer(customGSON)
        assertSame customGSON, deserializer.gson
    }

    @Test(expected = IllegalArgumentException)
    void testGsonConstructorNullArgument() {
        new GsonDeserializer(null)
    }

    @Test
    void testDeserialize() {
        def expected = [hello: '世界']
        assertEquals expected, deser('{"hello":"世界"}')
    }

    @Test
    void testDeserializeThrows() {
        def ex = new IOException('foo')
        deserializer = new GsonDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                throw ex
            }
        }
        try {
            deser('{"hello":"世界"}')
            fail()
        } catch (DeserializationException expected) {
            String msg = 'Unable to deserialize: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }

    @Test
    void testLong() {
        def json = '{"hello":42}'
        def m = deser(json) as Map
        def val = m.hello
        assertTrue val instanceof Long
        assertEquals 42L, val
    }

    @Test
    void testDouble() {
        // one more than Long can handle:
        def dval = 42.0 as double
        def json = '{"hello":' + dval + '}'
        def m = deser(json) as Map
        def val = m.hello
        assertTrue val instanceof Double
        assertEquals(dval, ((Double) val).doubleValue(), 0)
    }

    private void assertDuplicateRejected(String json, String name) {
        try {
            deser(json)
            fail()
        } catch (DeserializationException expected) {
            assertTrue expected.message.startsWith('Unable to deserialize: ')
            assertTrue expected.message.contains("Duplicate JSON member name '" + name + "'")
        }
    }

    @Test
    void testDuplicateMemberName() {
        assertDuplicateRejected('{"sub":"alice","sub":"attacker"}', 'sub')
    }

    @Test
    void testDuplicateMemberNameInNestedObject() {
        assertDuplicateRejected('{"user":{"id":1,"id":2}}', 'id')
    }

    @Test
    void testDuplicateMemberNameInArrayElement() {
        assertDuplicateRejected('{"list":[{"k":"a","k":"b"}]}', 'k')
    }

    @Test
    void testSameMemberNameInSiblingObjects() {
        // not duplicates - each name is unique within its own object:
        def expected = [x: [k: 1L], y: [k: 2L]]
        assertEquals expected, deser('{"x":{"k":1},"y":{"k":2}}')
    }

    @Test
    void testSameMemberNameInSiblingArrayElements() {
        def expected = [l: [[k: 1L], [k: 2L]]]
        assertEquals expected, deser('{"l":[{"k":1},{"k":2}]}')
    }

    private void assertTrailingContentRejected(String json) {
        // Gson asserts full consumption only when it creates the JsonReader itself, so supplying our own reader
        // must keep that check:
        try {
            deser(json)
            fail()
        } catch (DeserializationException expected) {
            assertTrue expected.message.startsWith('Unable to deserialize: ')
        }
    }

    @Test
    void testTrailingContentRejected() {
        assertTrailingContentRejected('{"sub":"alice"}trailing')
    }

    @Test
    void testTrailingDocumentRejected() {
        assertTrailingContentRejected('{"a":1} {"b":2}')
    }

    @Test
    void testDuplicateMemberNameWithCustomGson() {
        // a caller-supplied Gson instance retains Gson's default behavior of using the last value:
        deserializer = new GsonDeserializer(new Gson())
        def m = deser('{"sub":"alice","sub":"attacker"}') as Map
        assertEquals 'attacker', m.sub
    }

    @Test
    void testIOExceptionWhenCheckingForTrailingContent() {
        // the value itself parses, and the stream fails only when the trailing content check reads past it:
        def reader = new FilterReader(new StringReader('{"sub":"alice"}')) {
            @Override
            int read(char[] cbuf, int off, int len) throws IOException {
                int count = super.read(cbuf, off, len)
                if (count == -1) throw new IOException('read failure')
                return count
            }
        }
        try {
            deserializer.deserialize(reader)
            fail()
        } catch (DeserializationException expected) {
            assertTrue expected.message.startsWith('Unable to deserialize: ')
            assertTrue expected.cause instanceof JsonIOException
            assertEquals 'read failure', expected.cause.cause.message
        }
    }
}
