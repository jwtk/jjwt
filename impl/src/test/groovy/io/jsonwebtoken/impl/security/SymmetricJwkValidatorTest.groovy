package io.jsonwebtoken.impl.security


import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

class SymmetricJwkValidatorTest {

    static SymmetricJwkValidator validator() {
        return new SymmetricJwkValidator()
    }

    @Test(expected = MalformedKeyException)
    void testNullK() {
        def jwk = new DefaultSymmetricJwk()
        validator().validate(jwk)
    }

    @Test(expected = MalformedKeyException)
    void testEmptyK() {
        def jwk = new DefaultSymmetricJwk()
        jwk.put('k', ' ')
        validator().validate(jwk)
    }

    @Test
    void testValid() {
        def jwk = new DefaultSymmetricJwk().setK('k')
        validator().validate(jwk)
    }
}
