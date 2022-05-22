package io.jsonwebtoken.impl.security

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.lang.Maps
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.*

class DefaultValueGetterTest {

    @Test
    void testMapName() {
        def getter = new DefaultValueGetter(Maps.of('foo', 'bar').build())
        assertEquals 'Map', getter.name()
    }

    @Test
    void testJwtName() {
        def getter = new DefaultValueGetter(new DefaultHeader().setAlgorithm('foo'))
        assertEquals 'JWT header', getter.name()
    }

    @Test
    void testJwsName() {
        def getter = new DefaultValueGetter(new DefaultJwsHeader().setAlgorithm('foo'))
        assertEquals 'JWS header', getter.name()
    }

    @Test
    void testJweName() {
        def getter = new DefaultValueGetter(new DefaultJweHeader().setAlgorithm('foo'))
        assertEquals 'JWE header', getter.name()
    }

    @Test
    void testJwkName() {
        def ctx = new DefaultJwkContext().setId('id')
        def getter = new DefaultValueGetter(ctx)
        assertEquals 'JWK', getter.name()
    }

    @Test
    void testSecretJwkName() {
        def key = TestKeys.A128GCM
        def jwk = new DefaultSecretJwk(new DefaultJwkContext<SecretKey>().setType('oct').setKey(key))
        def getter = new DefaultValueGetter(jwk)
        assertEquals 'Secret JWK', getter.name()
    }

    @Test
    void testJwkContextName() {
        def ctx = new DefaultJwkContext<>().setId('id')
        def getter = new DefaultValueGetter(ctx)
        assertEquals 'JWK', getter.name()
    }

    @Test
    void testMalformedJwkContext() {
        def ctx = new DefaultJwkContext<>().setId('id')
        ctx.put('foo', 42)
        def getter = new DefaultValueGetter(ctx)
        try {
            getter.getRequiredString('foo')
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "JWK 'foo' value must be a String. Actual type: java.lang.Integer"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testMalformedJwk() {
        def jwk = Jwks.builder().setKey(TestKeys.A128GCM).put('foo', 42).build()
        def getter = new DefaultValueGetter(jwk)
        try {
            getter.getRequiredString('foo')
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Secret JWK 'foo' value must be a String. Actual type: java.lang.Integer"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetRequiredStringWhenEmpty() {
        def getter = new DefaultValueGetter(Maps.of('foo', '  ').build())
        try {
            getter.getRequiredString('foo')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Map 'foo' string value cannot be null or empty."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetRequiredIntegerWrongType() {
        def getter = new DefaultValueGetter(Maps.of('foo', 'bar').build())
        try {
            getter.getRequiredInteger('foo')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Map 'foo' value must be an Integer. Actual type: java.lang.String"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetRequiredPositiveIntegerWhenZero() {
        def getter = new DefaultValueGetter(Maps.of('foo', 0 as int).build())
        try {
            getter.getRequiredPositiveInteger('foo')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Map 'foo' value must be a positive Integer. Value: 0"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetRequiredPositiveIntegerWhenNegative() {
        def getter = new DefaultValueGetter(Maps.of('foo', Integer.MIN_VALUE).build())
        try {
            getter.getRequiredPositiveInteger('foo')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Map 'foo' value must be a positive Integer. Value: ${Integer.MIN_VALUE}"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetRequiredBytesInvalidData() {
        def getter = new DefaultValueGetter(Maps.of('foo', '#@!').build())
        try {
            getter.getRequiredBytes('foo')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Map 'foo' value is not a valid Base64URL String: Unable to decode input: "
            // cannot do msg equality check here - the trailing value differs depending on the JDK < 11 or >= 11,
            // so we do a 'starts with' check to ensure the parts of the message in our control are verified:
            assertTrue expected.getMessage().startsWith(msg)
        }
    }

    @Test
    void testGetRequiredBigIntNotSensitive() {
        def getter = new DefaultValueGetter(Maps.of('foo', '#@!').build())
        try {
            getter.getRequiredBigInt('foo', false)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Unable to decode Map 'foo' value '#@!' to BigInteger: Unable to decode input: "
            // cannot do msg equality check here - the trailing value differs depending on the JDK < 11 or >= 11,
            // so we do a 'starts with' check to ensure the parts of the message in our control are verified:
            assertTrue expected.getMessage().startsWith(msg)
        }
    }

    @Test
    void testGetRequiredBigIntSensitive() {
        def getter = new DefaultValueGetter(Maps.of('foo', '#@!').build())
        try {
            getter.getRequiredBigInt('foo', true)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Unable to decode Map 'foo' value to BigInteger: Unable to decode input: "
            // cannot do msg equality check here - the trailing value differs depending on the JDK < 11 or >= 11,
            // so we do a 'starts with' check to ensure the parts of the message in our control are verified:
            assertTrue expected.getMessage().startsWith(msg)
        }
    }

    @Test
    void testGetRequiredMap() {
        def map = Maps.of('bar', 'baz').build()
        def getter = new DefaultValueGetter(Maps.of('foo', map).build())
        assertSame map, getter.getRequiredMap('foo')
    }

    @Test
    void testGetRequiredMapWithInvalidValue() {
        def getter = new DefaultValueGetter(Maps.of('foo', 'bar').build())
        try {
            getter.getRequiredMap('foo')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "Map 'foo' value must be a Map. Actual type: java.lang.String"
            assertEquals msg, expected.getMessage()
        }
    }
}
