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
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeySetException
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class DefaultJwkSetParserBuilderTest {

    private Parser<JwkSet> parser

    private static void assertMalformed(String msg, Closure<?> c) {
        try {
            c()
            fail()
        } catch (MalformedKeySetException expected) {
            assertEquals msg, expected.message
        }
    }

    private void assertMalformed(String input, String msg) {
        assertMalformed(msg, { parser.parse(input) })
    }

    private static void assertEmpty(JwkSet result) {
        JwkSetConverterTest.assertEmpty(result)
    }

    private static DefaultJwkSetParserBuilder builder() {
        return new DefaultJwkSetParserBuilder()
    }

    @Before
    void setUp() {
        parser = builder().build()
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
        assertMalformed '{}', "Missing required ${DefaultJwkSet.KEYS} parameter."
    }

    @Test
    void testJsonObjectWithoutKeysMember() {
        assertMalformed '{"answerToLife":42}', "Missing required ${DefaultJwkSet.KEYS} parameter."
    }

    @Test
    void testKeysMemberNull() {
        assertMalformed '{"keys":null}', "JWK Set ${DefaultJwkSet.KEYS} value cannot be null."
    }

    @Test
    void testKeysMemberNonCollection() {
        String msg = "JWK Set ${DefaultJwkSet.KEYS} value must be a Collection (JSON Array). Type found: " +
                "java.lang.Integer"
        assertMalformed '{"keys":42}', msg
    }

    @Test
    void testKeysMemberEmptyCollection() {
        assertMalformed '{"keys":[]}', "JWK Set ${DefaultJwkSet.KEYS} collection cannot be empty."
    }

    @Test
    void testKeysMemberCollectionWithNullElement() {
        assertEmpty parser.parse('{"keys":[null]}')
    }

    @Test
    void testKeysMemberCollectionWithNullElementNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        assertMalformed '{"keys":[null]}', "JWK Set keys[0]: JWK cannot be null."
    }

    @Test
    void testKeysMemberCollectionWithNonObjectElement() {
        assertEmpty parser.parse('{"keys":[42]}')
    }

    @Test
    void testKeysMemberCollectionWithNonObjectElementNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        String msg = "JWK Set keys[0]: JWK must be a Map<String,?> (JSON Object). Type found: java.lang.Integer."
        assertMalformed '{"keys":[42]}', msg
    }

    @Test
    void testKeysMemberCollectionWithEmptyObjectElement() {
        assertEmpty parser.parse('{"keys":[{}]}')
    }

    @Test
    void testKeysMemberCollectionWithEmptyObjectElementNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter."
        assertMalformed '{"keys":[{}]}', msg
    }

    @Test
    void testJwkWithMissingKty() {
        assertEmpty parser.parse('{"keys":[{"hello":42}]}')
    }

    @Test
    void testJwkWithMissingKtyNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter."
        assertMalformed '{"keys":[{"hello":42}]}', msg
    }

    @Test
    void testJwkWithNullKty() {
        assertEmpty parser.parse('{"keys":[{"kty":null}]}')
    }

    @Test
    void testJwkWithNullKtyNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        String msg = "JWK Set keys[0]: JWK ${AbstractJwk.KTY} value cannot be null."
        assertMalformed '{"keys":[{"kty":null}]}', msg
    }

    @Test
    void testJwkWithEmptyKty() {
        assertEmpty parser.parse('{"keys":[{"kty":""}]}')
    }

    @Test
    void testJwkWithEmptyKtyNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        String msg = "JWK Set keys[0]: JWK ${AbstractJwk.KTY} value cannot be empty."
        assertMalformed '{"keys":[{"kty":""}]}', msg
    }

    @Test
    void testKeysElementWithMissingKeyMaterial() {
        assertEmpty parser.parse('{"keys":[{"kty":"oct"}]}')
    }

    @Test
    void testKeysElementWithMissingKeyMaterialNotIgnored() {
        parser = builder().ignoreUnsupported(false).build()
        String msg = "JWK Set keys[0]: Secret JWK is missing required ${DefaultSecretJwk.K} value."
        assertMalformed '{"keys":[{"kty":"oct"}]}', msg
    }
}
