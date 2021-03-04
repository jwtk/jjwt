package io.jsonwebtoken.impl.security

import org.junit.Test
import static org.junit.Assert.*

class DefaultSymmetricJwkTest {

    @Test
    void testType() {
        assertEquals 'oct', DefaultSymmetricJwk.TYPE_VALUE
        assertEquals DefaultSymmetricJwk.TYPE_VALUE, new DefaultSymmetricJwk().getType()
    }

    @Test
    void testSetNullK() {
        try {
            new DefaultSymmetricJwk().setK(null)
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals "SymmetricJwk 'k' property cannot be null or empty.", e.getMessage()
        }
    }

    @Test
    void testSetEmptyK() {
        try {
            new DefaultSymmetricJwk().setK(' ')
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals "SymmetricJwk 'k' property cannot be null or empty.", e.getMessage()
        }
    }

    @Test
    void testK() {
        def jwk = new DefaultSymmetricJwk()
        assertEquals 'k', DefaultSymmetricJwk.K
        String val = UUID.randomUUID().toString()
        jwk.setK(val)
        assertEquals val, jwk.get(DefaultSymmetricJwk.K)
        assertEquals val, jwk.getK()
    }
}
