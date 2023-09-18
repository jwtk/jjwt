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
import org.junit.Before
import org.junit.Test

import static org.hamcrest.CoreMatchers.instanceOf
import static org.junit.Assert.*

class JacksonSerializerTest {

    private JacksonSerializer serializer

    @Before
    void setUp() {
         serializer = new JacksonSerializer()
    }

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assertThat(serializer, instanceOf(JacksonSerializer))
    }

    @Test
    void testDefaultConstructor() {
        assertSame JacksonWriter.DEFAULT_OBJECT_MAPPER,  serializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        ObjectMapper customOM = new ObjectMapper()
        def serializer = new JacksonSerializer(customOM)
        assertSame customOM, serializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonSerializer<>(null)
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = new JacksonSerializer().serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testSerializeFailsWithJsonProcessingException() {

        def ex = new IOException('foo')
        def serializer = new JacksonSerializer() {
            @Override
            protected void writeValue(Object o, Writer writer) throws IOException {
                throw ex
            }
        }
        try {
            serializer.serialize([hello: 'world'])
            fail()
        } catch (SerializationException se) {
            assertEquals 'Unable to serialize object: Unable to write value as bytes: foo', se.getMessage()
            assertTrue se.cause instanceof JsonProcessingException
        }
    }
}
