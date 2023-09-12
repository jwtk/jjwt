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
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.KeyOperationPolicy
import io.jsonwebtoken.security.MalformedKeySetException
import org.junit.Before
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

class DefaultJwkSetBuilderTest {

    private DefaultJwkSetBuilder builder

    static final Map<String, ?> SECRET_JWK_MAP = [
            kty: 'oct',
            k  : Encoders.BASE64URL.encode(TestKeys.HS256.getEncoded())
    ]

    private static void assertIllegal(String msg, def c) {
        try {
            c()
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals msg, expected.message
        }
    }

    private static void assertMalformed(String msg, def c) {
        try {
            c()
            fail()
        } catch (MalformedKeySetException expected) {
            assertEquals msg, expected.message
        }
    }

    @Before
    void setUp() {
        builder = new DefaultJwkSetBuilder()
    }

    @Test
    void testStaticFactoryMethod() {
        assertTrue Jwks.set() instanceof DefaultJwkSetBuilder
    }

    @Test
    void testEmpty() {
        String msg = "Missing required ${DefaultJwkSet.KEYS} parameter."
        assertMalformed msg, { builder.build() }
    }

    @Test
    void testNonEmptyWithoutKeys() {
        String msg = "Missing required ${DefaultJwkSet.KEYS} parameter."
        assertMalformed msg, { builder.add('one', 'one').build() }
    }

    @Test
    void testAddEntry() {
        builder.add('one', 'one')
        builder.add('keys', [SECRET_JWK_MAP])
        def set = builder.build()
        assertEquals 'one', set.one
    }

    @Test
    void testDeleteEntry() {
        builder.add('one', 'one')
        builder.add('two', 'two')
        builder.delete('two')
        builder.add('keys', [SECRET_JWK_MAP])
        def set = builder.build()
        assertEquals 2, set.size() // 'one' + 'keys'
        assertEquals 'one', set.one
    }

    @Test
    void testBuilderEmpty() {
        def set = builder.add('one', 'one').add('two', 'two')
                .empty() // clear everything out
                .add('keys', [SECRET_JWK_MAP]).build()
        assertEquals 1, set.size() // only 'keys' remains
        assertTrue set.containsKey('keys')
    }

    @Test
    void testAddMap() {
        def m = [one: 'one', two: 'two']
        def set = builder.add(m).add('keys', [SECRET_JWK_MAP]).build()
        assertEquals 3, set.size() // 'one' + 'two' + 'keys'
        assertEquals 'one', set.one
        assertEquals 'two', set.two
        assertTrue set.containsKey('keys')
    }

    /**
     * Asserts that a raw map put('keys',val) (not using the .add(jwk), .add(collection) or .keys methods) still
     * converts to JWKs
     */
    @Test
    void testPutKeysSingle() {
        def key = TestKeys.HS256
        def jwkMap = [
                kty: 'oct',
                k  : Encoders.BASE64URL.encode(key.getEncoded())
        ]
        def jwk = Jwks.builder().key(key).build()
        def expected = [jwk] as Set
        def set = builder.add('keys', [jwkMap]).build()
        assertEquals expected, set.getKeys()
    }

    /**
     * Asserts that a raw map put('keys', val) (not using the .add(jwk), .add(collection) or .keys methods) still
     * converts to JWKs
     */
    @Test
    void testPutKeysMultiple() {
        def key1 = TestKeys.HS256
        def jwk1Map = [
                kty: 'oct',
                k  : Encoders.BASE64URL.encode(key1.getEncoded())
        ]
        def key2 = TestKeys.HS384
        def jwk2Map = [
                kty: 'oct',
                k  : Encoders.BASE64URL.encode(key2.getEncoded())
        ]
        def jwk1 = Jwks.builder().key(key1).build()
        def jwk2 = Jwks.builder().key(key2).build()
        def expected = [jwk1, jwk2] as Set
        def set = builder.add('keys', [jwk1Map, jwk2Map]).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testAddKeySingle() {
        def key = TestKeys.HS256
        def jwk = Jwks.builder().key(key).build()
        def expected = [jwk] as Set
        def set = builder.add(jwk).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testAddKeyNull() {
        def key = TestKeys.HS256
        def jwk = Jwks.builder().key(key).build()
        def expected = [jwk] as Set
        assertNotNull builder.add((Jwk<? extends Key>) null) // no exception thrown
        def set = builder.add(jwk).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testAddKeyMultiple() {
        def key1 = TestKeys.HS256
        def key2 = TestKeys.HS384
        def jwk1 = Jwks.builder().key(key1).build()
        def jwk2 = Jwks.builder().key(key2).build()
        def expected = [jwk1, jwk2] as Set
        def set = builder.add(jwk1).add(jwk2).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testAddKeysSingle() {
        def key = TestKeys.HS256
        def jwk = Jwks.builder().key(key).build()
        def expected = [jwk] as Set
        def set = builder.add(expected).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testAddKeysMultiple() {
        def key1 = TestKeys.HS256
        def key2 = TestKeys.HS384
        def jwk1 = Jwks.builder().key(key1).build()
        def jwk2 = Jwks.builder().key(key2).build()
        def expected = [jwk1, jwk2] as Set
        def set = builder.add(expected).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testAddKeysEmpty() {
        def key1 = TestKeys.HS256
        def key2 = TestKeys.HS384
        def jwk1 = Jwks.builder().key(key1).build()
        def jwk2 = Jwks.builder().key(key2).build()
        def expected = [jwk1, jwk2] as Set
        assertNotNull builder.add([]) // no exception thrown
        def set = builder.add(expected).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testSetKeysSingle() {
        def key = TestKeys.HS256
        def jwk = Jwks.builder().key(key).build()
        def expected = [jwk] as Set
        def set = builder.keys(expected).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testSetKeysMultiple() {
        def key1 = TestKeys.HS256
        def key2 = TestKeys.HS384
        def jwk1 = Jwks.builder().key(key1).build()
        def jwk2 = Jwks.builder().key(key2).build()
        def expected = [jwk1, jwk2] as Set
        def set = builder.keys(expected).build()
        assertEquals expected, set.getKeys()
    }

    @Test
    void testKeysFullReplacement() {
        def key1 = TestKeys.HS256
        def key2 = TestKeys.HS384
        def jwk1 = Jwks.builder().key(key1).build()
        def jwk2 = Jwks.builder().key(key2).build()
        def expected = [jwk2] as Set
        def set = builder.add(jwk1).keys(expected).build() // jwk1 won't be in the result
        assertEquals expected, set.getKeys()
    }

    @Test
    void testProvider() {
        def key = TestKeys.HS256
        def provider = TestKeys.BC
        def jwkMap = [
                kty: 'oct',
                k  : Encoders.BASE64URL.encode(key.getEncoded())
        ]
        def jwk = Jwks.builder().provider(provider).key(key).build()
        def set = builder.provider(TestKeys.BC).add('keys', [jwkMap]).build()
        assertEquals jwk, set.getKeys().iterator().next()
    }

    @Test
    void testDefaultKeyOperationPolicy() {

        // default policy
        def key = TestKeys.HS256
        def goodMap = [
                kty    : 'oct',
                k      : Encoders.BASE64URL.encode(key.getEncoded()),
                key_ops: ['sign']
        ]
        builder.add('keys', [goodMap]).build() // no exception

        def badMap = [
                kty    : 'oct',
                k      : Encoders.BASE64URL.encode(key.getEncoded()),
                key_ops: ['sign', 'encrypt'] // unrelated operations
        ]

        String msg = "Invalid Map ${DefaultJwkSet.KEYS} value: <redacted>. Unable to create JWK: Unrelated key " +
                "operations are not allowed. KeyOperation [${Jwks.OP.ENCRYPT}] is unrelated to " +
                "[${Jwks.OP.SIGN}]."

        assertIllegal msg, { builder.add('keys', [badMap]).build() }
    }

    @Test
    void testCustomKeyOperationPolicy() {
        def key = TestKeys.HS256
        def badMap = [
                kty    : 'oct',
                k      : Encoders.BASE64URL.encode(key.getEncoded()),
                key_ops: ['sign', 'encrypt'] // unrelated, but we'll allow next:
        ]
        def policy = new DefaultKeyOperationPolicy(Jwks.OP.get().values(), true) // unrelated allowed
        builder = builder.operationPolicy(policy) as DefaultJwkSetBuilder
        builder.add('keys', [badMap]).build() // no exception thrown
    }

    @Test
    void testNullPolicy() {
        builder.operationPolicy(null)
        // assert that the default policy has been applied instead of null:
        def defaultPolicy = AbstractJwkBuilder.DEFAULT_OPERATION_POLICY
        // ensure default has been applied instead of null:
        assertSame defaultPolicy, builder.operationPolicy
        assertSame defaultPolicy, builder.converter.JWK_CONVERTER.supplier.operationPolicy
    }

    @Test
    void testPolicyChangeValidatesExistingJwks() {
        def key = TestKeys.HS256
        def badMap = [
                kty    : 'oct',
                k      : Encoders.BASE64URL.encode(key.getEncoded()),
                key_ops: ['sign', 'encrypt'] // unrelated, but we'll allow next:
        ]
        KeyOperationPolicy policy = Jwks.OP.policy().allowUnrelated(true).build()
        def jwk = Jwks.builder().operationPolicy(policy).add(badMap).build()

        builder.operationPolicy(policy)
        builder.add(jwk) // allowed due to less restrictive policy

        //now enable new more restrictive policy:
        policy = AbstractJwkBuilder.DEFAULT_OPERATION_POLICY
        String msg = "Unrelated key operations are not allowed. KeyOperation " +
                "[${Jwks.OP.ENCRYPT}] is unrelated to [${Jwks.OP.SIGN}]."
        assertIllegal msg, { builder.operationPolicy(policy) }
    }
}
