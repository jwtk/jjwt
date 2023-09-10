package io.jsonwebtoken.impl.security

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.jackson.io.JacksonDeserializer
import io.jsonwebtoken.security.KeyOperationPolicy
import io.jsonwebtoken.security.MalformedKeySetException
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultJwkSetParserTest {

    static Deserializer<Map<String, ?>> DESERIALIZER = new JacksonDeserializer<>()
    static KeyOperationPolicy POLICY = AbstractJwkBuilder.DEFAULT_OPERATION_POLICY
    private DefaultJwkSetParser parser

    @Before
    void setUp() {
        parser = new DefaultJwkSetParser(null, DESERIALIZER, POLICY);
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
        parser = new DefaultJwkSetParser(null, deserializer, POLICY)

        try {
            parser.parse('foo')
        } catch (MalformedKeySetException expected) {
            String msg = "Unable to deserialize content to a JWK Set: foo"
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
            String msg = "Missing required JWK Set 'keys' member.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJsonObjectWithoutKeysMember() {
        try {
            parser.parse('{"answerToLife":42}')
        } catch (MalformedKeySetException expected) {
            String msg = "Missing required JWK Set 'keys' member.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberNull() {
        try {
            parser.parse('{"keys":null}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set 'keys' value cannot be null.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberNonCollection() {
        try {
            parser.parse('{"keys":42}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set 'keys' value must be a Collection (JSON Array). Type found: " +
                    "java.lang.Integer";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberEmptyCollection() {
        try {
            parser.parse('{"keys":[]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set 'keys' value is empty.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberCollectionWithNullElement() {
        try {
            parser.parse('{"keys":[null]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0] element is null.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberCollectionWithNonObjectElement() {
        try {
            parser.parse('{"keys":[42]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0] element is not a JSON Object. Type found: java.lang.Integer";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysMemberCollectionWithEmptyObjectElement() {
        try {
            parser.parse('{"keys":[{}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0] element is an empty JSON Object.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwkWithMissingKty() {
        try {
            parser.parse('{"keys":[{"hello":42}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwkWithNullKty() {
        try {
            parser.parse('{"keys":[{"kty":null}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testJwkWithEmptyKty() {
        try {
            parser.parse('{"keys":[{"kty":""}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testKeysElementWithMissingKeyMaterial() {
        try {
            parser.parse('{"keys":[{"kty":"oct"}]}')
        } catch (MalformedKeySetException expected) {
            String msg = "JWK Set keys[0]: Secret JWK is missing required ${DefaultSecretJwk.K} value.";
            assertEquals msg, expected.message
        }
    }
}
