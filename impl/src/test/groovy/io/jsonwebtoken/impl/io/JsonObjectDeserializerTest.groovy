/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.*

class JsonObjectDeserializerTest {

    /**
     * It's possible for JSON parsers to throw a StackOverflowError when body is deeply nested. Since it's possible
     * across multiple parsers, JJWT handles the exception when parsing.*/
    @Test
    void testStackOverflowError() {
        def err = new StackOverflowError('foo')
        // create one that will throw a StackOverflowError
        def deser = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                fail() // shouldn't be called in this test
                return null
            }

            @Override
            Object deserialize(Reader reader) throws DeserializationException {
                throw err
            }
        }
        try {
            // doesn't matter for this test, just has to be non-null:
            def r = new StringReader(Strings.EMPTY)
            new JsonObjectDeserializer(deser, 'claims').apply(r)
            fail()
        } catch (DeserializationException e) {
            String msg = String.format(JsonObjectDeserializer.MALFORMED_COMPLEX_ERROR, 'claims', 'claims', 'foo')
            assertEquals msg, e.message
        }
    }

    /**
     * Check that a DeserializationException is wrapped and rethrown as a MalformedJwtException with a developer friendly message.*/
    @Test
    void testDeserializationExceptionMessage() {
        def ex = new IOException('foo')
        // create one that will throw a StackOverflowError
        def deser = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                fail() // should not be called in this test
                return null
            }

            @Override
            Object deserialize(Reader reader) throws DeserializationException {
                throw ex
            }
        }
        try {
            // doesn't matter for this test, just has to be non-null:
            def r = new StringReader(Strings.EMPTY)
            new JsonObjectDeserializer(deser, 'claims').apply(r)
            fail()
        } catch (MalformedJwtException e) {
            String msg = String.format(JsonObjectDeserializer.MALFORMED_ERROR, 'claims', 'foo')
            assertEquals msg, e.message
            assertSame ex, e.cause
        }
    }
}
