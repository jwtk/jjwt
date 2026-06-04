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

import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.cfg.MapperBuilder

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class Jackson3SerializerTest {

    private Jackson3Serializer ser

    @Before
    void setUp() {
        ser = new Jackson3Serializer()
    }

    byte[] serialize(def value) {
        def os = new ByteArrayOutputStream()
        ser.serialize(value, os)
        return os.toByteArray()
    }

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assertTrue serializer instanceof Jackson3Serializer
    }

    @Test
    void testDefaultConstructor() {
        assertSame Jackson3Serializer.DEFAULT_OBJECT_MAPPER.serializationConfig().getSubtypeResolver().getClass(), ser.objectMapper.serializationConfig().getSubtypeResolver().getClass()
    }

    @Test
    void testObjectMapperConstructor() {
        ObjectMapper customOM = new ObjectMapper()
        ser = new Jackson3Serializer(customOM)
        assertNotSame customOM, ser.objectMapper;

        assertEquals customOM.serializationConfig().getSubtypeResolver().getClass(),
                ser.objectMapper.serializationConfig().getSubtypeResolver().getClass();
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new Jackson3Serializer<>(null)
    }

    @Test
    void testObjectMapperConstructorAutoRegistersModule() {
        ObjectMapper om = createMock(ObjectMapper)
        MapperBuilder builder = createMock(MapperBuilder)

        expect(om.rebuild()).andReturn(builder)
        expect(builder.addModule(same(Jackson3Serializer.MODULE))).andReturn(builder)
        expect(builder.build()).andReturn(om)

        replay om, builder

        new Jackson3Serializer<>(om)

        verify om, builder
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = ser.serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testByte() {
        byte[] expected = Strings.utf8("120") //ascii("x") = 120
        byte[] bytes = Strings.utf8("x")
        assertArrayEquals expected, serialize(bytes[0]) // single byte
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = Strings.utf8("hi")
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        assertEquals expected, Strings.utf8(serialize(bytes))
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        byte[] result = serialize(bytes)
        assertEquals '""', Strings.utf8(result)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = serialize('h' as char)
        assertEquals "\"h\"", Strings.utf8(result)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = serialize('hi'.toCharArray())
        assertEquals "\"hi\"", Strings.utf8(result)
    }

    @Test
    void testWriteObject() {
        byte[] expected = Strings.utf8('{"hello":"世界"}' as String)
        byte[] result = serialize([hello: '世界'])
        assertArrayEquals expected, result
    }
}
