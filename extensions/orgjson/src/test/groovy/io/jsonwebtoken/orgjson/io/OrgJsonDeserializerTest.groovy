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
package io.jsonwebtoken.orgjson.io

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class OrgJsonDeserializerTest {

    private OrgJsonDeserializer des

    private Object fromBytes(byte[] data) {
        return des.deserialize(new ByteArrayInputStream(data))
    }

    private Object read(String s) {
        return fromBytes(Strings.utf8(s))
    }

    @Test(expected = IllegalArgumentException)
    void testNullArgument() {
        des.deserialize((InputStream) null)
    }

    @Test(expected = DeserializationException)
    void testEmptyByteArray() {
        fromBytes(new byte[0])
    }

    @Test(expected = DeserializationException)
    void testInvalidJson() {
        read('"')
    }

    @Test
    void testLiteralNull() {
        assertNull read('null')
    }

    @Test
    void testLiteralTrue() {
        assertTrue read('true') as boolean
    }

    @Test
    void testLiteralFalse() {
        assertFalse read('false') as boolean
    }

    @Test
    void testLiteralInteger() {
        assertEquals 1 as Integer, read('1')
    }

    @Test
    void testLiteralDecimal() {
        assertEquals 3.14159 as Double, read('3.14159') as BigDecimal, 0d
    }

    @Test
    void testEmptyArray() {
        def value = read('[]')
        assert value instanceof List
        assertEquals 0, value.size()
    }

    @Test
    void testSimpleArray() {
        def value = read('[1, 2]')
        assert value instanceof List
        def expected = [1, 2]
        assertEquals expected, value
    }

    @Test
    void testArrayWithNullElements() {
        def value = read('[1, null, 3]')
        assert value instanceof List
        def expected = [1, null, 3]
        assertEquals expected, value
    }

    @Test
    void testEmptyObject() {
        def value = read('{}')
        assert value instanceof Map
        assertEquals 0, value.size()
    }

    @Test
    void testSimpleObject() {
        def value = read('{"hello": "世界"}')
        assert value instanceof Map
        def expected = [hello: '世界']
        assertEquals expected, value
    }

    @Test
    void testObjectWithKeyHavingNullValue() {
        def value = read('{"hello": "世界", "test": null}')
        assert value instanceof Map
        def expected = [hello: '世界', test: null]
        assertEquals expected, value
    }

    @Test
    void testObjectWithKeyHavingArrayValue() {
        def value = read('{"hello": "世界", "test": [1, 2]}')
        assert value instanceof Map
        def expected = [hello: '世界', test: [1, 2]]
        assertEquals expected, value
    }

    @Test
    void testObjectWithKeyHavingObjectValue() {
        def value = read('{"hello": "世界", "test": {"foo": "bar"}}')
        assert value instanceof Map
        def expected = [hello: '世界', test: [foo: 'bar']]
        assertEquals expected, value
    }

    @Before
    void setUp() {
        des = new OrgJsonDeserializer()
    }

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assert deserializer instanceof OrgJsonDeserializer
    }

    @Test
    void deserialize() {
        def m = [hello: 42]
        assertEquals m, des.deserialize(Strings.utf8('{"hello":42}'))
    }

    @Test(expected = IllegalArgumentException)
    void deserializeNull() {
        des.deserialize((InputStream) null)
    }

    @Test(expected = DeserializationException)
    void deserializeEmpty() {
        read('')
    }

    @Test
    void throwableConvertsToDeserializationException() {

        def t = new Throwable("foo")

        des = new OrgJsonDeserializer() {
            @Override
            protected Object doDeserialize(InputStream inputStream) {
                throw t
            }
        }

        try {
            des.deserialize(Strings.utf8('whatever'))
            fail()
        } catch (DeserializationException expected) {
            String msg = 'Unable to deserialize: foo'
            assertEquals msg, expected.message
        }
    }

}
