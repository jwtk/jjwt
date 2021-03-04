package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CurveIds
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

class PrivateEcJwkValidatorTest {

    static PrivateEcJwkValidator validator() {
        return new PrivateEcJwkValidator()
    }

    @Test(expected = MalformedKeyException)
    void testNullD() {
        def jwk = new DefaultPrivateEcJwk().setCurveId(CurveIds.P521).setX('x').setY('y')
        validator().validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testEmptyD() {
        def jwk = new DefaultPrivateEcJwk().setCurveId(CurveIds.P521).setX('x').setY('y')
        jwk.put('d', ' ')
        validator().validate(jwk)
    }

    @Test
    void testValid() {
        def jwk = new DefaultPrivateEcJwk().setCurveId(CurveIds.P521).setX('x').setY('y').setD('d')
        validator().validate(jwk)
    }
}
