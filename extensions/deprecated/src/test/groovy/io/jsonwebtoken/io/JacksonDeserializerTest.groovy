/*
 * Copyright (C) 2019 jsonwebtoken.io
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
import org.junit.Test

import java.lang.reflect.Field

import static org.hamcrest.CoreMatchers.instanceOf
import static org.hamcrest.CoreMatchers.sameInstance
import static org.hamcrest.MatcherAssert.assertThat

class JacksonDeserializerTest {

    @Test
    void testSimpleConstructor() {
        // it extends the newly moved class
        assertThat new JacksonDeserializer(), instanceOf(io.jsonwebtoken.jackson.io.JacksonDeserializer)
    }

    @Test
    void testCustomObjectMapper() {
        Field field = io.jsonwebtoken.jackson.io.JacksonDeserializer.getDeclaredField("objectMapper")
        field.setAccessible(true)

        def mapper = new ObjectMapper()
        def serializer = new JacksonDeserializer(mapper)
        assertThat field.get(serializer), sameInstance(mapper)
    }
}
