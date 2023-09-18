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
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class GsonDeserializerTest {

    private GsonDeserializer deserializer

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
    void testObjectMapperConstructor() {
        def customGSON = new Gson()
        def deserializer = new GsonDeserializer(customGSON)
        assertSame customGSON, deserializer.gson
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new GsonDeserializer<>(null)
    }

    @Test
    void testDeserialize() {
        def expected = [hello: '世界']
        assertEquals expected, deserializer.deserialize(Strings.utf8('{"hello":"世界"}'))
    }

    @Test
    void testDeserializeFailsWithJsonProcessingException() {
        def ex = new IOException('foo')
        deserializer = new GsonDeserializer() {
            @Override
            protected Object readValue(byte[] bytes) throws IOException {
                throw ex
            }
        }
        try {
            deserializer.deserialize(Strings.utf8('{"hello":"世界"}'))
            fail()
        } catch (DeserializationException expected) {
            String msg = 'Unable to deserialize JSON: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }
}
