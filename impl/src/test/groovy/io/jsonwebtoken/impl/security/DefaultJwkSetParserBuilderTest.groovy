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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Parser
import io.jsonwebtoken.jackson.io.JacksonDeserializer
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeySetException
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class DefaultJwkSetParserBuilderTest {

    static Deserializer<Map<String, ?>> DESERIALIZER = new JacksonDeserializer<>()
    private Parser<JwkSet> parser

    @Before
    void setUp() {
        parser = new DefaultJwkSetParserBuilder().deserializer(DESERIALIZER).build()
    }

    @Test
    void testStaticFactoryMethod() {
        assertTrue Jwks.setParser() instanceof DefaultJwkSetParserBuilder
    }

    /**
     * Asserts that a deserialization problem is represented as a MalformedKeySetException
     */
    @Test
    void testDeserializeException() {
        def deserializer = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                throw new DeserializationException("foo")
            }
        }
        parser = new DefaultJwkSetParserBuilder().deserializer(deserializer).build()

        try {
            parser.parse('foo')
        } catch (MalformedKeySetException expected) {
            String msg = "Unable to deserialize JWK Set: foo"
            assertEquals msg, expected.message
        }
    }

    @Test(expected = MalformedKeySetException)
    void testJsonNull() {
        parser.parse('null')
    }

    @Test(expected = MalformedKeySetException)
    void testNonJSONObject() {
        parser.parse('42')
    }

    @Test(expected = MalformedKeySetException)
    void testInvalidJSONObjectWithoutStringKeys() {
        parser.parse('{42:42}') // non-string key
    }

    @Test
    void testEmptyJsonObject() {
        try {
            parser.parse('{}')
        } catch (MalformedKeySetException expected) {
            String msg = "Missing required ${DefaultJwkSet.KEYS} parameter."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJsonObjectWithoutKeysMember() {
        try {
            parser.parse('{"answerToLife":42}')
        } catch (MalformedKeySetException expected) {
            String msg = "Missing required ${DefaultJwkSet.KEYS} parameter."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberNull() {
        try {
            parser.parse('{"keys":null}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set ${DefaultJwkSet.KEYS} value cannot be null."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberNonCollection() {
        try {
            parser.parse('{"keys":42}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set ${DefaultJwkSet.KEYS} value must be a Collection (JSON Array). Type found: " +
                    "java.lang.Integer"
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberEmptyCollection() {
        try {
            parser.parse('{"keys":[]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set ${DefaultJwkSet.KEYS} collection cannot be empty."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberCollectionWithNullElement() {
        try {
            parser.parse('{"keys":[null]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK cannot be null."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberCollectionWithNonObjectElement() {
        try {
            parser.parse('{"keys":[42]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK must be a Map<String,?> (JSON Object). Type found: java.lang.Integer."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberCollectionWithEmptyObjectElement() {
        try {
            parser.parse('{"keys":[{}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwkWithMissingKty() {
        try {
            parser.parse('{"keys":[{"hello":42}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwkWithNullKty() {
        try {
            parser.parse('{"keys":[{"kty":null}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK ${AbstractJwk.KTY} value cannot be null."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwkWithEmptyKty() {
        try {
            parser.parse('{"keys":[{"kty":""}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK ${AbstractJwk.KTY} value cannot be empty."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysElementWithMissingKeyMaterial() {
        try {
            parser.parse('{"keys":[{"kty":"oct"}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: Secret JWK is missing required ${DefaultSecretJwk.K} value."
            assertEquals msg, expected.message
        }
    }
}
