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

    @Test
    void testIOExceptionConvertedToSerializationException() {
        def ex = new IOException('foo')
        s = new GsonSerializer() {
            @Override
            protected byte[] writeValueAsBytes(Object o) throws IOException {
                throw ex
            }
        }
        try {
            ser(new Object())
            fail()
        } catch (SerializationException expected) {
            String causeMsg = 'foo'
            String msg = "Unable to serialize object: $causeMsg"
            assertEquals causeMsg, expected.cause.message
            assertEquals msg, expected.message
        }
    }
}
