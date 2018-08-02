package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CurveIds
import io.jsonwebtoken.security.MalformedKeyException
import io.jsonwebtoken.security.PublicEcJwk
import org.junit.Test

class AbstractEcJwkValidatorTest {

    static AbstractEcJwkValidator<PublicEcJwk> VALIDATOR =
            DefaultPublicEcJwkBuilder.VALIDATOR as AbstractEcJwkValidator<PublicEcJwk>

    @Test
    void testValid() {
        def jwk = new DefaultPublicEcJwk().setCurveId(CurveIds.P256).setX('x').setY('y')
        VALIDATOR.validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testIncorrectType() {
        def jwk = new DefaultPublicEcJwk()
        jwk.put('kty', 'foo')
        VALIDATOR.validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testNullCurveId() {
        def jwk = new DefaultPublicEcJwk().setX('x').setY('y')
        VALIDATOR.validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testNullX() {
        def jwk = new DefaultPublicEcJwk().setCurveId(CurveIds.P521)
        VALIDATOR.validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testEmptyX() {
        def jwk = new DefaultPublicEcJwk().setCurveId(CurveIds.P521)
        jwk.put('x', ' ')
        VALIDATOR.validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testNullY() {
        def jwk = new DefaultPublicEcJwk().setCurveId(CurveIds.P521).setX('x')
        VALIDATOR.validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testEmptyY() {
        def jwk = new DefaultPublicEcJwk().setCurveId(CurveIds.P521).setX('x')
        jwk.put('y', ' ')
        VALIDATOR.validate(jwk)
    }
}
