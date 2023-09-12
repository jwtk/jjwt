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

import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.MalformedKeySetException
import io.jsonwebtoken.security.SecretJwk
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class JwkSetConverterTest {

    private JwkSetConverter converter

    @Before
    void setUp() {
        converter = new JwkSetConverter()
    }

    private void assertIllegal(Object input, String msg) {
        try {
            converter.applyFrom(input)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals msg, expected.message
        }
    }

    private void assertMalformed(Object input, String msg) {
        try {
            converter.applyFrom(input)
            fail()
        } catch (MalformedKeySetException expected) {
            assertEquals msg, expected.message
        }
    }

    static void assertEmpty(JwkSet result) {
        // bad input ignored by default per https://www.rfc-editor.org/rfc/rfc7517.html#section-5 :
        assertEquals 0, result.size()
        assertEquals 0, result.getKeys().size()
        assertFalse result.getKeys().iterator().hasNext()
        assertFalse result.iterator().hasNext()
    }

    @Test
    void testApplyToNull() {
        assertNull converter.applyTo(null)
    }

    @Test
    void testApplyToNonNull() {
        def set = new DefaultJwkSet(DefaultJwkSet.KEYS, Collections.emptyMap())
        assertSame set, converter.applyTo(set)
    }

    @Test
    void testNull() {
        assertIllegal null, "Value cannot be null."
    }

    @Test
    void testNonMap() {
        def value = 42
        String msg = "Value must be a Map<String,?> (JSON Object). Type found: ${value.class.name}."
        assertIllegal 42, msg
    }

    @Test
    void testEmptyMap() {
        assertMalformed [:], "Missing required ${DefaultJwkSet.KEYS} parameter."
    }

    @Test
    void testKeysMissing() {
        def m = ['hello': 'world']
        assertMalformed m, "Missing required ${DefaultJwkSet.KEYS} parameter."
    }

    @Test
    void testKeysNull() {
        def m = [keys: null]
        assertMalformed m, "JWK Set ${DefaultJwkSet.KEYS} value cannot be null."
    }

    @Test
    void testKeysNonCollection() {
        def val = 42
        def m = [keys: val]
        String msg = "JWK Set ${DefaultJwkSet.KEYS} value must be a Collection (JSON Array). " +
                "Type found: ${val.class.name}"
        assertMalformed m, msg
    }

    @Test
    void testKeysEmpty() {
        def m = [keys: []]
        assertMalformed m, "JWK Set ${DefaultJwkSet.KEYS} collection cannot be empty."
    }

    @Test
    void testMapWithNullKey() {
        def m = new LinkedHashMap()
        m.put(null, 'foo')
        m.put('keys', [42])
        assertIllegal m, "JWK Set map key cannot be null."
    }

    @Test
    void testMapWithNonStringKey() {
        def key = 42
        def m = new LinkedHashMap()
        m.put(key, 42)
        m.put('keys', [42])
        String msg = "JWK Set map keys must be Strings. Encountered key '${key}' of type ${key.class.name}"
        assertIllegal m, msg

    }

    @Test
    void testJwkNull() {
        def m = [keys: [null]]
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testJwkNullNotIgnored() {
        converter = new JwkSetConverter(false)
        def m = [keys: [null]]
        assertMalformed m, "JWK Set keys[0]: JWK cannot be null."
    }

    @Test
    void testJwkNotAJSONObject() {
        def val = 42
        def m = [keys: [val]]
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testJwkNotAJSONObjectNotIgnored() {
        converter = new JwkSetConverter(false)
        def val = 42
        def m = [keys: [val]]
        String msg = "JWK Set keys[0]: JWK must be a Map<String,?> (JSON Object). Type found: ${val.class.name}."
        assertMalformed m, msg
    }

    @Test
    void testJwkEmpty() {
        def val = [:]
        def m = [keys: [val]]
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testJwkEmptyNotIgnored() {
        converter = new JwkSetConverter(false)
        def val = [:]
        def m = [keys: [val]]
        String msg = "JWK Set keys[0]: JWK is missing required ${AbstractJwk.KTY} parameter."
        assertMalformed m, msg
    }

    @Test
    void testJwkKtyNonString() {
        def val = 42
        def jwk = [kty: val]
        def m = [keys: [jwk]]
        // bad input ignored by default per https://www.rfc-editor.org/rfc/rfc7517.html#section-5 :
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testJwkKtyNonStringNotIgnored() {
        converter = new JwkSetConverter(false)
        def val = 42
        def jwk = [kty: val]
        def m = [keys: [jwk]]
        String msg = "JWK Set keys[0]: JWK ${AbstractJwk.KTY} value must be a String. Type found: ${val.class.name}"
        assertMalformed m, msg
    }

    @Test
    void testJwkKtyEmpty() {
        def val = ''
        def jwk = [kty: val]
        def m = [keys: [jwk]]
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testJwkKtyEmptyNotIgnored() {
        converter = new JwkSetConverter(false)
        def val = ''
        def jwk = [kty: val]
        def m = [keys: [jwk]]
        String msg = "JWK Set keys[0]: JWK ${AbstractJwk.KTY} value cannot be empty."
        assertMalformed m, msg
    }

    @Test
    void testJwkMissingKeyMaterial() {
        def jwk = [kty: 'oct'] // missing 'k' parameter
        def m = [keys: [jwk]]
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testJwkMissingKeyMaterialNotIgnored() {
        converter = new JwkSetConverter(false)
        def jwk = [kty: 'oct'] // missing 'k' parameter
        def m = [keys: [jwk]]
        String msg = "JWK Set keys[0]: Secret JWK is missing required ${DefaultSecretJwk.K} value."
        assertMalformed m, msg
    }

    /**
     * Asserts that our exception message shows which key in the keys array failed.
     */
    @Test
    void testExceptionMessageIncrements() {
        converter = new JwkSetConverter(false)
        def k = Encoders.BASE64URL.encode(TestKeys.HS256.getEncoded())
        def good = [kty: 'oct', k: k]
        def bad = [kty: 'oct']
        def m = [keys: [good, bad]]
        String msg = "JWK Set keys[1]: Secret JWK is missing required ${DefaultSecretJwk.K} value."
        assertMalformed m, msg
    }

    @Test
    void testUnsupportedJwk() {
        def m = [keys: [[kty: 'foo']]]
        assertEmpty converter.applyFrom(m)
    }

    @Test
    void testUnsupportedNotIgnored() {
        converter = new JwkSetConverter(false)
        def m = [keys: [[kty: 'foo']]]
        try {
            converter.applyFrom(m)
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = "JWK Set keys[0]: Unable to create JWK for unrecognized kty value 'foo': there is no known " +
                    "JWK Factory capable of creating JWKs for this key type."
            assertEquals msg, expected.message
        }
    }

    /**
     * Asserts that our exception message shows which key in the keys array failed.
     */
    @Test
    void testJwkSucceeds() {
        def k = Encoders.BASE64URL.encode(TestKeys.HS256.getEncoded())
        def good = [kty: 'oct', k: k]
        def m = [keys: [good]]
        def jwkSet = converter.applyFrom(m)
        assertNotNull jwkSet
        assertNotNull jwkSet.getKeys()
        assertEquals 1, jwkSet.getKeys().size()
        assertTrue jwkSet.getKeys().iterator().next() instanceof SecretJwk
    }

    @Test
    void testApplyFromExistingJwkSet() {
        def k = Encoders.BASE64URL.encode(TestKeys.HS256.getEncoded())
        def good = [kty: 'oct', k: k]
        def m = [keys: [good]]
        def jwkSet = converter.applyFrom(m)
        assertSame jwkSet, converter.applyFrom(jwkSet)
    }
}
