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
package io.jsonwebtoken.io

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class JacksonDeserializerTest {

    @Test
    void testDefaultConstructor() {
        def deserializer = new JacksonDeserializer()
        assertNotNull deserializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        def deserializer = new JacksonDeserializer(customOM)
        assertSame customOM, deserializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonDeserializer<>(null)
    }

    @Test
    void testDeserialize() {
        byte[] serialized = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        def expected = [hello: '世界']
        def result = new JacksonDeserializer().deserialize(serialized)
        assertEquals expected, result
    }

    @Test
    void testDeserializeFailsWithJsonProcessingException() {

        def ex = createMock(java.io.IOException)

        expect(ex.getMessage()).andReturn('foo')

        def deserializer = new JacksonDeserializer() {
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
