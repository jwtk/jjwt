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

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.jackson.testkit.AbstractJacksonDeserializerTest

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
        return new ObjectMapper()
    }

    @Override
    protected Object defaultObjectMapper() {
        return JacksonSerializer.DEFAULT_OBJECT_MAPPER
    }

    @Override
    protected Class<? extends Throwable> duplicateMemberExceptionType() {
        return JsonParseException
    }

    @Override
    protected String duplicateMemberMessage(String memberName) {
        return "Duplicate field '$memberName'"
    }

    @Override
    protected String duplicateMemberLocation(int line, int column) {
        return "line: $line, column: $column"
    }
}
