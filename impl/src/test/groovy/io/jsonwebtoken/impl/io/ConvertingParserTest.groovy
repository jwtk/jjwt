/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.impl.io

import io.jsonwebtoken.impl.lang.Function
import io.jsonwebtoken.impl.lang.Functions
import io.jsonwebtoken.impl.security.JwkConverter
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class ConvertingParserTest {

    /**
     * Asserts that if a non-DeserializationException is thrown during deserialization, that it is wrapped in a
     * DeserializationException
     */
    @Test
    void testDeserializeNonDeserializationException() {
        def cause = new IllegalArgumentException("test")
        def deserializer = new Deserializer<Map<String, ?>>() {
            @Override
            Map<String, ?> deserialize(byte[] bytes) throws DeserializationException {
                throw cause
            }
        }
        def parser = new ConvertingParser(deserializer, JwkConverter.ANY,
                Functions.identity() as Function<Throwable, RuntimeException>)

        try {
            parser.parse('foo')
        } catch (DeserializationException expected) {
            String msg = "Unable to deserialize JSON: test"
            assertEquals msg, expected.getMessage()
            assertSame cause, expected.cause
        }
    }
}
