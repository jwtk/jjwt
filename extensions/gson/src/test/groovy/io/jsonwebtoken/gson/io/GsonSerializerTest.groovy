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
package io.jsonwebtoken.gson.io

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.lang.Supplier
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class GsonSerializerTest {

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assertTrue serializer instanceof GsonSerializer
    }

    @Test
    void testDefaultConstructor() {
        def serializer = new GsonSerializer()
        assertNotNull serializer.gson
    }

    @Test
    void testGsonConstructor() {
        def customGSON = new GsonBuilder()
                .registerTypeHierarchyAdapter(Supplier.class, GsonSupplierSerializer.INSTANCE)
                .disableHtmlEscaping().create()
        def serializer = new GsonSerializer<>(customGSON)
        assertSame customGSON, serializer.gson
    }

    @Test
    void testGsonConstructorWithIncorrectlyConfiguredGson() {
        try {
            //noinspection GroovyResultOfObjectAllocationIgnored
            new GsonSerializer<>(new Gson())
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Invalid Gson instance - it has not been registered with the necessary ' +
                    'io.jsonwebtoken.lang.Supplier type adapter.  When using the GsonBuilder, ensure this type ' +
                    'adapter is registered by calling ' +
                    'gsonBuilder.registerTypeHierarchyAdapter(io.jsonwebtoken.lang.Supplier.class, ' +
                    'io.jsonwebtoken.gson.io.GsonSupplierSerializer.INSTANCE) before calling gsonBuilder.create()'
            assertEquals msg, expected.message
        }
    }

    @Test(expected = IllegalArgumentException)
    void testConstructorWithNullArgument() {
        new GsonSerializer<>(null)
    }

    @Test
    void testByte() {
        byte[] expected = "120".getBytes(Strings.UTF_8) //ascii("x") = 120
        byte[] bytes = "x".getBytes(Strings.UTF_8)
        byte[] result = new GsonSerializer().serialize(bytes[0]) //single byte
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = "hi".getBytes(Strings.UTF_8)
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        byte[] result = new GsonSerializer().serialize(bytes)
        assertEquals expected, new String(result, Strings.UTF_8)
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        byte[] result = new GsonSerializer().serialize(bytes)
        assertEquals '""', new String(result, Strings.UTF_8)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = new GsonSerializer().serialize('h' as char)
        assertEquals "\"h\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = new GsonSerializer().serialize("hi".toCharArray())
        assertEquals "\"hi\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = new GsonSerializer().serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }


    @Test
    void testSerializeFailsWithJsonProcessingException() {

        def ex = createMock(SerializationException)

        expect(ex.getMessage()).andReturn('foo')

        def serializer = new GsonSerializer() {
            @Override
            protected byte[] writeValueAsBytes(Object o) throws SerializationException {
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
