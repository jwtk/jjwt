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
package io.jsonwebtoken.jackson2.io

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.jackson.testkit.AbstractJacksonSerializerTest
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertSame

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
        return new ObjectMapper()
    }

    @Override
    protected Object defaultObjectMapper() {
        return JacksonSerializer.DEFAULT_OBJECT_MAPPER
    }

    @Test
    void testObjectMapperConstructor() {
        ObjectMapper customOM = new ObjectMapper()
        ser = new JacksonSerializer(customOM)
        assertSame customOM, ser.objectMapper
    }

    @Test
    void testObjectMapperConstructorAutoRegistersModule() {
        ObjectMapper om = createMock(ObjectMapper)
        expect(om.registerModule(same(JacksonSerializer.MODULE))).andReturn(om)
        replay om
        //noinspection GroovyResultOfObjectAllocationIgnored
        new JacksonSerializer<>(om)
        verify om
    }
}
