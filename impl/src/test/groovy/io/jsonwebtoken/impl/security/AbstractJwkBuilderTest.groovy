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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import io.jsonwebtoken.security.SecretJwk
import org.junit.Test

import javax.crypto.SecretKey
import java.security.Key

import static org.junit.Assert.*

class AbstractJwkBuilderTest {

    private static final SecretKey SKEY = TestKeys.A256GCM

    private static AbstractJwkBuilder<SecretKey, SecretJwk, AbstractJwkBuilder> builder() {
        return (AbstractJwkBuilder) Jwks.builder().key(SKEY)
    }

    @Test
    void testKeyType() {
        def jwk = builder().build()
        assertEquals 'oct', jwk.getType()
        assertNotNull jwk.k // JWA id for raw key value
    }

    @Test
    void testPut() {
        def a = UUID.randomUUID()
        def builder = builder()
        builder.put('foo', a)
        assertEquals a, builder.build().get('foo')
    }

    @Test
    void testPutAll() {
        def foo = UUID.randomUUID()
        def bar = UUID.randomUUID().toString() //different type
        def m = [foo: foo, bar: bar]
        def jwk = builder().add(m).build()
        assertEquals foo, jwk.foo
        assertEquals bar, jwk.bar
    }

    @Test
    void testRemove() {
        def jwk = builder().add('foo', 'bar').delete('foo').build() as Jwk
        assertNull jwk.get('foo')
    }

    @Test
    void testClear() {
        def builder = builder().add('foo', 'bar')
        builder.clear()
        def jwk = builder.build()
        assertNull jwk.get('foo')
    }

    @Test
    void testEmpty() {
        def jwk = builder().add('foo', 'bar').empty().build() as Jwk
        assertNull jwk.get('foo')
    }

    @Test
    void testAlgorithm() {
        def alg = 'someAlgorithm'
        def jwk = builder().algorithm(alg).build()
        assertEquals alg, jwk.getAlgorithm()
        assertEquals alg, jwk.alg //test raw get via JWA member id
    }

    @Test
    void testAlgorithmByPut() {
        def alg = 'someAlgorithm'
        def jwk = builder().add('alg', alg).build() //ensure direct put still is handled properly
        assertEquals alg, jwk.getAlgorithm()
        assertEquals alg, jwk.alg //test raw get via JWA member id
    }

    @Test
    void testId() {
        def kid = UUID.randomUUID().toString()
        def jwk = builder().id(kid).build()
        assertEquals kid, jwk.getId()
        assertEquals kid, jwk.kid //test raw get via JWA member id
    }

    @Test
    void testIdByPut() {
        def kid = UUID.randomUUID().toString()
        def jwk = builder().add('kid', kid).build()
        assertEquals kid, jwk.getId()
        assertEquals kid, jwk.kid //test raw get via JWA member id
    }

    @Test
    //ensures that even if a raw single String value is present, it is represented as a Set per the JWA spec (string array)
    void testOperationsByPutSingleStringValue() {
        def s = 'wrapKey'
        def op = Jwks.OP.get().get(s)
        def canonical = Collections.setOf(s)
        def idiomatic = Collections.setOf(op)
        def jwk = builder().add('key_ops', s).build() // <-- put uses single raw String value, not a set
        assertEquals idiomatic, jwk.getOperations() // <-- still get an idiomatic set
        assertEquals canonical, jwk.key_ops         // <-- still get a canonical set
    }

    @Test
    //ensures that even if a raw single KeyOperation value is present, it is represented as a Set per the JWA spec (string array)
    void testOperationsByPutSingleIdiomaticValue() {
        def s = 'wrapKey'
        def op = Jwks.OP.get().get(s)
        def canonical = Collections.setOf(s)
        def idiomatic = Collections.setOf(op)
        def jwk = builder().add('key_ops', op).build() // <-- put uses single raw KeyOperation value, not a set
        assertEquals idiomatic, jwk.getOperations() // <-- still get an idiomatic set
        assertEquals canonical, jwk.key_ops         // <-- still get a canonical set
    }

    @Test
    void testOperation() {
        def s = 'wrapKey'
        def op = Jwks.OP.get().get(s)
        def canonical = Collections.setOf(s)
        def idiomatic = Collections.setOf(op)
        def jwk = builder().operation(op).build()
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
    }

    @Test
    void testOperationCustom() {
        def s = UUID.randomUUID().toString()
        def op = Jwks.OP.builder().id(s).build()
        def canonical = Collections.setOf(s)
        def idiomatic = Collections.setOf(op)
        def jwk = builder().operation(op).build()
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
    }

    @Test
    void testOperationCustomOverridesDefault() {
        def s = 'sign'
        def op = Jwks.OP.builder().id(s).related('verify').build()
        def canonical = Collections.setOf(s)
        def idiomatic = Collections.setOf(op)
        def jwk = builder().operation(op).build()
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
        assertSame op, jwk.getOperations().iterator().next()

        //now assert that the standard VERIFY operation treats this as related since it has the same ID:
        canonical = Collections.setOf(s, 'verify')
        idiomatic = Collections.setOf(op, Jwks.OP.VERIFY)
        jwk = builder().operation(op).operation(Jwks.OP.VERIFY).build() as Jwk
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
    }

    @Test
    void testOperations() {
        def a = 'sign'
        def b = 'verify'
        def canonical = Collections.setOf(a, b)
        def idiomatic = Collections.setOf(Jwks.OP.SIGN, Jwks.OP.VERIFY)
        def jwk = builder().operations(idiomatic).build()
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
    }

    @Test
    void testOperationsUnrelated() {
        try {
            // exception thrown on setter, before calling build:
            builder().operations(Collections.setOf(Jwks.OP.SIGN, Jwks.OP.ENCRYPT))
            fail()
        } catch (IllegalArgumentException e) {
            String msg = 'Unrelated key operations are not allowed. KeyOperation [\'encrypt\' (Encrypt content)] is ' +
                    'unrelated to [\'sign\' (Compute digital signature or MAC)].'
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testOperationsPutUnrelatedStrings() {
        try {
            builder().add('key_ops', ['sign', 'encrypt']).build()
            fail()
        } catch (MalformedKeyException e) {
            String msg = 'Unable to create JWK: Unrelated key operations are not allowed. KeyOperation ' +
                    '[\'encrypt\' (Encrypt content)] is unrelated to [\'sign\' (Compute digital signature or MAC)].'
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testOperationsByCanonicalPut() {
        def a = 'encrypt'
        def b = 'decrypt'
        def canonical = Collections.setOf(a, b)
        def idiomatic = Collections.setOf(Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT)
        def jwk = builder().add('key_ops', canonical).build() // Set of String values, not KeyOperation objects
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
    }

    @Test
    void testOperationsByIdiomaticPut() {
        def a = 'encrypt'
        def b = 'decrypt'
        def canonical = Collections.setOf(a, b)
        def idiomatic = Collections.setOf(Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT)
        def jwk = builder().add('key_ops', idiomatic).build() // Set of KeyOperation values, not strings
        assertEquals idiomatic, jwk.getOperations()
        assertEquals canonical, jwk.key_ops
    }

    @Test
    void testCustomOperationOverridesDefault() {
        def op = Jwks.OP.builder().id('sign').description('Different Description')
                .related(Jwks.OP.VERIFY.id).build()
        def builder = builder().operationPolicy(Jwks.OP.policy().add(op).build())
        def jwk = builder.operations(Collections.setOf(op, Jwks.OP.VERIFY)).build() as Jwk
        assertSame op, jwk.getOperations().find({it.id == 'sign'})
    }

    @Test
    void testProvider() {
        def provider = TestKeys.BC
        def jwk = builder().provider(provider).build()
        assertEquals 'oct', jwk.getType()
        assertSame provider, jwk.@context.@provider
    }

    @Test
    void testFactoryThrowsIllegalArgumentException() {
        def ctx = new DefaultJwkContext()
        ctx.put('whatevs', 42)
        //noinspection GroovyUnusedAssignment
        JwkFactory factory = new JwkFactory() {
            JwkContext newContext(JwkContext src, Key key) {
                return null
            }

            @Override
            Jwk createJwk(JwkContext jwkContext) {
                throw new IllegalArgumentException("foo")
            }
        }
        def builder = new AbstractJwkBuilder(ctx, factory) {}
        try {
            builder.build()
        } catch (MalformedKeyException expected) {
            assertEquals 'Unable to create JWK: foo', expected.getMessage()
        }
    }
}
