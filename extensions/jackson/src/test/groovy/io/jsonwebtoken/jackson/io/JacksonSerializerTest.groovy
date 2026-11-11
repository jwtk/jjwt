/*
 * Copyright © 2026 jsonwebtoken.io
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
import io.jsonwebtoken.jackson.testkit.AbstractJacksonSerializerTest
import org.junit.Test
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.SerializationFeature
import tools.jackson.databind.json.JsonMapper

import static org.junit.Assert.*

class JacksonSerializerTest extends AbstractJacksonSerializerTest {

    @Override
    protected Serializer newSerializer() {
        return new JacksonSerializer()
    }

    @Override
    protected Serializer newSerializer(Object objectMapper) {
        return new JacksonSerializer((ObjectMapper) objectMapper)
    }

    @Override
    protected Object newObjectMapper() {
        return JsonMapper.builder().build()
    }

    @Override
    protected Object defaultObjectMapper() {
        return JacksonSerializer.DEFAULT_OBJECT_MAPPER
    }

    @Test
    void testObjectMapperConstructorNeverModifiesArgument() {
        ObjectMapper customOM = JsonMapper.builder().build()
        ser = new JacksonSerializer(customOM)
        assertNotSame customOM, ser.objectMapper
        assertTrue customOM.registeredModules().isEmpty()
        assertEquals([JacksonSerializer.MODULE], ser.objectMapper.registeredModules() as List)
    }

    @Test
    void testObjectMapperConstructorRetainsConfiguration() {
        ObjectMapper customOM = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build()
        ser = new JacksonSerializer(customOM)
        assertTrue ser.objectMapper.isEnabled(SerializationFeature.INDENT_OUTPUT)
        assertTrue ser.objectMapper instanceof JsonMapper
    }
}
