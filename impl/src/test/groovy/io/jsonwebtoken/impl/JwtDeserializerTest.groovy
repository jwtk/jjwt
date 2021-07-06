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
package io.jsonwebtoken.impl

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.IOException
import org.junit.Assert
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.mock
import static org.easymock.EasyMock.replay
import static org.junit.Assert.assertEquals

class JwtDeserializerTest {

    /**
     * It's common for JSON parsers to throw a StackOverflowError when body is deeply nested. Since it's common
     * across multiple parsers, JJWT handles the exception when parsing.
     */
    @Test
    void testParserStackOverflowError() {

        String json = '{"test": "testParserStackOverflowError"}'
        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8)

        // create a Deserializer that will throw a StackOverflowError
        Deserializer<Map<String,?>> deserializer = mock(Deserializer)
        expect(deserializer.deserialize(jsonBytes)).andThrow(new StackOverflowError("Test exception: testParserStackOverflowError" ))
        replay(deserializer)

        try {
            new JwtDeserializer<>(deserializer).deserialize(jsonBytes)
            Assert.fail("Expected IOException")
        } catch (IOException e) {
            assertEquals JwtDeserializer.MALFORMED_COMPLEX_ERROR + json, e.message
        }
    }

    /**
     * Check that a DeserializationException is wrapped and rethrown as a MalformedJwtException with a developer friendly message.
     */
    @Test
    void testDeserializationExceptionMessage() {

        String json = '{"test": "testDeserializationExceptionMessage"}'
        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8)

        // create a Deserializer that will throw a DeserializationException
        Deserializer<Map<String,?>> deserializer = mock(Deserializer)
        expect(deserializer.deserialize(jsonBytes)).andThrow(new DeserializationException("Test exception: testDeserializationExceptionMessage" ))
        replay(deserializer)

        try {
            new JwtDeserializer<>(deserializer).deserialize(jsonBytes)
            Assert.fail("Expected MalformedJwtException")
        } catch (MalformedJwtException e) {
            assertEquals JwtDeserializer.MALFORMED_ERROR + json, e.message
        }
    }
}
