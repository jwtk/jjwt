package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.KeyException
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.interfaces.ECPublicKey

import static org.junit.Assert.*

class AbstractFamilyJwkFactoryTest {

    @Test
    void testGenerateKeyPropagatesKeyException() {
        // any AbstractFamilyJwkFactory subclass will do:
        def factory = new EcPublicJwkFactory()
        def ctx = new DefaultJwkContext()
        ctx.put('hello', 'world')
        def ex = new MalformedKeyException('foo')
        try {
            factory.generateKey(ctx, new CheckedFunction<KeyFactory, ECPublicKey>() {
                @Override
                ECPublicKey apply(KeyFactory keyFactory) throws Exception {
                    throw ex
                }
            })
            fail()
        } catch (KeyException expected) {
            assertSame ex, expected
        }
    }

    @Test
    void testGenerateKeyUnexpectedException() {
        // any AbstractFamilyJwkFactory subclass will do:
        def factory = new EcPublicJwkFactory()
        def ctx = new DefaultJwkContext()
        ctx.put('hello', 'world')
        try {
            factory.generateKey(ctx, new CheckedFunction<KeyFactory, ECPublicKey>() {
                @Override
                ECPublicKey apply(KeyFactory keyFactory) throws Exception {
                    throw new NoSuchAlgorithmException("foo")
                }
            })
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals 'Unable to create ECPublicKey from JWK {hello=world}: foo', expected.getMessage()
        }
    }

    @Test
    void testUnsupportedContext() {
        def factory = new EcPublicJwkFactory() {
            @Override
            boolean supports(JwkContext<?> ctx) {
                return false
            }
        }
        try {
            factory.createJwk(new DefaultJwkContext<ECPublicKey>())
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals 'Unsupported JwkContext.', iae.getMessage()
        }
    }
}
