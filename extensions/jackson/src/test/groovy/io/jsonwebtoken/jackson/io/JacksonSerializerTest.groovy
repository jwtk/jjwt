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
package io.jsonwebtoken.jackson.io

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.hamcrest.CoreMatchers.instanceOf
import static org.junit.Assert.*

class JacksonSerializerTest {

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assertThat(serializer, instanceOf(JacksonSerializer))
    }

    @Test
    void testDefaultConstructor() {
        def serializer = new JacksonSerializer()
        assertNotNull serializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        def serializer = new JacksonSerializer<>(customOM)
        assertSame customOM, serializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonSerializer<>(null)
    }

    @Test
    void testObjectMapperConstructorAutoRegistersModule() {
        def om = createMock(ObjectMapper)
        expect(om.registerModule(same(JacksonSerializer.MODULE))).andReturn(om)
        replay om
        def serializer = new JacksonSerializer<>(om)
        verify om
    }

    @Test
    void testByte() {
        byte[] expected = "120".getBytes(Strings.UTF_8) //ascii("x") = 120
        byte[] bytes = "x".getBytes(Strings.UTF_8)
        byte[] result = new JacksonSerializer().serialize(bytes[0]) //single byte
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = "hi".getBytes(Strings.UTF_8)
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        byte[] result = new JacksonSerializer().serialize(bytes)
        assertEquals expected, new String(result, Strings.UTF_8)
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        byte[] result = new JacksonSerializer().serialize(bytes)
        assertEquals '""', new String(result, Strings.UTF_8)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = new JacksonSerializer().serialize('h' as char)
        assertEquals "\"h\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = new JacksonSerializer().serialize("hi".toCharArray())
        assertEquals "\"hi\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = new JacksonSerializer().serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testSerializeFailsWithJsonProcessingException() {

        def ex = createMock(JsonProcessingException)

        expect(ex.getMessage()).andReturn('foo')

        def serializer = new JacksonSerializer() {
            @Override
            protected byte[] writeValueAsBytes(Object o) throws JsonProcessingException {
                throw ex
            }
        }

        replay ex

        try {
            serializer.serialize([hello: 'world'])
            fail()
        } catch (SerializationException se) {
            assertEquals 'Unable to serialize object: foo', se.getMessage()
            assertSame ex, se.getCause()
        }

        verify ex
    }
}
