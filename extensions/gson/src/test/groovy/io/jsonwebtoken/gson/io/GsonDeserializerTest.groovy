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
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import java.text.DecimalFormat
import java.text.NumberFormat

import static org.easymock.EasyMock.*
import static org.junit.Assert.*
import static org.hamcrest.CoreMatchers.instanceOf

class GsonDeserializerTest {

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assertThat(deserializer, instanceOf(GsonDeserializer))
    }

    @Test
    void testDefaultConstructor() {
        def deserializer = new GsonDeserializer()
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
        byte[] serialized = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        def expected = [hello: '世界']
        def result = new GsonDeserializer().deserialize(serialized)
        assertEquals expected, result
    }

    @Test
    void testDeserializeFailsWithJsonProcessingException() {

        def ex = createMock(java.io.IOException)

        expect(ex.getMessage()).andReturn('foo')

        def deserializer = new GsonDeserializer() {
            @Override
            protected Object readValue(byte[] bytes) throws java.io.IOException {
                throw ex
            }
        }

        replay ex

        try {
            deserializer.deserialize('{"hello":"世界"}'.getBytes(Strings.UTF_8))
            fail()
        } catch (DeserializationException se) {
            assertEquals 'Unable to deserialize bytes into a java.lang.Object instance: foo', se.getMessage()
            assertSame ex, se.getCause()
        }

        verify ex
    }
}
