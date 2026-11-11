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

import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.jackson.testkit.AbstractJacksonDeserializerTest
import io.jsonwebtoken.jackson.testkit.CustomBean
import io.jsonwebtoken.lang.Maps
import org.junit.Test
import tools.jackson.core.exc.StreamReadException
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.json.JsonMapper

import static org.junit.Assert.*

class JacksonDeserializerTest extends AbstractJacksonDeserializerTest {

    @Override
    protected Deserializer newDeserializer() {
        return new JacksonDeserializer()
    }

    @Override
    protected Deserializer newDeserializer(Object objectMapper) {
        return new JacksonDeserializer((ObjectMapper) objectMapper)
    }

    @Override
    protected Deserializer newDeserializer(Map<String, Class<?>> claimTypeMap) {
        return new JacksonDeserializer(claimTypeMap)
    }

    @Override
    protected Deserializer newDeserializer(Object objectMapper, Map<String, Class<?>> claimTypeMap) {
        return new JacksonDeserializer((ObjectMapper) objectMapper, claimTypeMap)
    }

    @Override
    protected Deserializer newFailingDeserializer(Exception e) {
        return new JacksonDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                throw e
            }
        }
    }

    @Override
    protected Object newObjectMapper() {
        return JsonMapper.builder().build()
    }

    @Override
    protected Object defaultObjectMapper() {
        return JacksonSerializer.DEFAULT_OBJECT_MAPPER
    }

    @Override
    protected Class<? extends Throwable> duplicateMemberExceptionType() {
        return StreamReadException
    }

    @Override
    protected String duplicateMemberMessage(String memberName) {
        return "Duplicate Object property \"$memberName\""
    }

    @Override
    protected String duplicateMemberLocation(int line, int column) {
        return 'byte offset: #UNKNOWN' // Jackson 3 does not report a line and column for this error
    }

    @Test
    void testObjectMapperAndClaimTypeMapConstructorNeverModifiesArgument() {
        ObjectMapper customOM = JsonMapper.builder().build()
        def deserializer = new JacksonDeserializer(customOM, Maps.of("custom", CustomBean).build())
        assertNotSame customOM, deserializer.objectMapper
        assertTrue customOM.registeredModules().isEmpty()
        assertEquals 1, deserializer.objectMapper.registeredModules().size()
    }

    @Test
    void testClaimTypeMapConstructorNeverModifiesDefaultObjectMapper() {
        def deserializer = new JacksonDeserializer(Maps.of("custom", CustomBean).build())
        assertNotSame JacksonSerializer.DEFAULT_OBJECT_MAPPER, deserializer.objectMapper
        assertEquals([JacksonSerializer.MODULE], JacksonSerializer.DEFAULT_OBJECT_MAPPER.registeredModules() as List)
        assertEquals 2, deserializer.objectMapper.registeredModules().size()
    }
}
