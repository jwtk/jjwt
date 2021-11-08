package io.jsonwebtoken.impl.security


import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import io.jsonwebtoken.security.SecretJwk
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.*

class AbstractJwkBuilderTest {

    private static final SecretKey SKEY = TestKeys.A256GCM

    private static AbstractJwkBuilder<SecretKey, SecretJwk, AbstractJwkBuilder> builder() {
        return (AbstractJwkBuilder)Jwks.builder().setKey(SKEY)
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
        def jwk = builder().putAll(m).build()
        assertEquals foo, jwk.foo
        assertEquals bar, jwk.bar
    }

    @Test
    void testAlgorithm() {
        def alg = 'someAlgorithm'
        def jwk = builder().setAlgorithm(alg).build()
        assertEquals alg, jwk.getAlgorithm()
        assertEquals alg, jwk.alg //test raw get via JWA member id
    }

    @Test
    void testAlgorithmByPut() {
        def alg = 'someAlgorithm'
        def jwk = builder().put('alg', alg).build() //ensure direct put still is handled properly
        assertEquals alg, jwk.getAlgorithm()
        assertEquals alg, jwk.alg //test raw get via JWA member id
    }

    @Test
    void testId() {
        def kid = UUID.randomUUID().toString()
        def jwk = builder().setId(kid).build()
        assertEquals kid, jwk.getId()
        assertEquals kid, jwk.kid //test raw get via JWA member id
    }

    @Test
    void testIdByPut() {
        def kid = UUID.randomUUID().toString()
        def jwk = builder().put('kid', kid).build()
        assertEquals kid, jwk.getId()
        assertEquals kid, jwk.kid //test raw get via JWA member id
    }

    @Test
    void testOperations() {
        def a = UUID.randomUUID().toString()
        def b = UUID.randomUUID().toString()
        def set = [a, b] as Set<String>
        def jwk = builder().setOperations(set).build()
        assertEquals set, jwk.getOperations()
        assertEquals set, jwk.key_ops
    }

    @Test
    void testOperationsByPut() {
        def a = UUID.randomUUID().toString()
        def b = UUID.randomUUID().toString()
        def set = [a, b] as Set<String>
        def jwk = builder().put('key_ops', set).build()
        assertEquals set, jwk.getOperations()
        assertEquals set, jwk.key_ops
    }

    @Test //ensures that even if a raw single value is present it is represented as a Set per the JWA spec (string array)
    void testOperationsByPutSingleValue() {
        def a = UUID.randomUUID().toString()
        def set = [a] as Set<String>
        def jwk = builder().put('key_ops', a).build() // <-- put uses single raw value, not a set
        assertEquals set, jwk.getOperations() // <-- still get a set
        assertEquals set, jwk.key_ops         // <-- still get a set
    }

    @Test
    void testProvider() {
        def provider = Providers.getBouncyCastleProviderIfPossible()
        def jwk = builder().setProvider(provider).build()
        assertEquals 'oct', jwk.getType()
    }

    @Test
    void testFactoryThrowsIllegalArgumentException() {
        def ctx = new DefaultJwkContext()
        ctx.put('whatevs', 42)
        //noinspection GroovyUnusedAssignment
        JwkFactory factory = new JwkFactory() {
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
