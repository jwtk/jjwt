package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test
import static org.junit.Assert.*

class AbstractJwkValidatorTest {

    static final String malformedMsg = "JWKs must have a key type ('kty') property value."

    @Test
    void testValidateWithNullType() {
        def jwk = new TestJwk()
        jwk.remove('kty')
        try {
            new TestJwkValidator<>().validate(jwk)
            fail()
        } catch (MalformedKeyException e) {
            assertEquals malformedMsg, e.getMessage()
        }
    }

    @Test
    void testValidateWithEmptyType() {
        def jwk = new TestJwk()
        jwk.put('kty', ' ')
        try {
            new TestJwkValidator<>().validate(jwk)
            fail()
        } catch (MalformedKeyException e) {
            assertEquals malformedMsg, e.getMessage()
        }
    }

    @Test
    void testIncorrectType() {
        def jwk = new TestJwk()
        jwk.put('kty', 'foo')
        try {
            new TestJwkValidator<>().validate(jwk)
            fail()
        } catch (MalformedKeyException e) {
            assertEquals "JWK does not have expected key type ('kty') value of 'test'. Value found: foo",
                    e.getMessage()
        }
    }

    @Test
    void testValid() {
        def jwk = new TestJwk()
        def validator = new TestJwkValidator()
        validator.validate(jwk)
        assertEquals jwk, validator.jwk
    }
}
