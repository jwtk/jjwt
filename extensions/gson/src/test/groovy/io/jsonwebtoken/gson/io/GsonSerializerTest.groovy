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
import com.google.gson.GsonBuilder
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.lang.Supplier
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class GsonSerializerTest {

    private GsonSerializer s

    @Before
    void setUp() {
        s = new GsonSerializer()
    }

    private String ser(Object o) {
        return Strings.utf8(s.serialize(o))
    }

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assert serializer instanceof GsonSerializer
    }

    @Test
    void testDefaultConstructor() {
        assertNotNull s.gson
    }

    @Test
    void testGsonConstructor() {
        def customGSON = new GsonBuilder()
                .registerTypeHierarchyAdapter(Supplier.class, GsonSupplierSerializer.INSTANCE)
                .disableHtmlEscaping().create()
        s = new GsonSerializer(customGSON)
        assertSame customGSON, s.gson
    }

    @Test
    void testSerialize() {
        assertEquals '"hello"', ser('hello')
    }

    private byte[] bytes(def o) {
        ByteArrayOutputStream out = new ByteArrayOutputStream()
        s.serialize(o, out)
        return out.toByteArray()
    }

    private String json(def o) {
        return Strings.utf8(bytes(o))
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
        byte[] expected = Strings.utf8("120") //ascii("x") = 120
        byte[] result = bytes(Strings.utf8("x")[0]) //single byte
        assertArrayEquals expected, result
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        assertEquals expected, json(Strings.utf8('hi'))
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] result = bytes(new byte[0])
        assertEquals '""', Strings.utf8(result)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        assertEquals '"h"', json('h' as char)
    }

    @Test
    void testCharArray() { //expect string by default:
        assertEquals '"hi"', json('hi'.toCharArray())
    }

    @Test
    void testWrite() {
        assertEquals '{"hello":"世界"}', json([hello: '世界'])
    }

    @Test
    void testWriteFailure() {
        def ex = new IOException('foo')
        s = new GsonSerializer() {
            @Override
            protected void doSerialize(Object o, OutputStream out) {
                throw ex
            }
        }
        try {
            ser([hello: 'world'])
            fail()
        } catch (SerializationException expected) {
            String msg = 'Unable to serialize object of type java.util.LinkedHashMap: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }

    @Test
    void testIOExceptionConvertedToSerializationException() {
        def ex = new IOException('foo')
        s = new GsonSerializer() {
            @Override
            protected void doSerialize(Object o, OutputStream out) {
                throw ex
            }
        }
        try {
            ser(new Object())
            fail()
        } catch (SerializationException expected) {
            String causeMsg = 'foo'
            String msg = "Unable to serialize object of type java.lang.Object: $causeMsg"
            assertEquals causeMsg, expected.cause.message
            assertEquals msg, expected.message
        }
    }
}
