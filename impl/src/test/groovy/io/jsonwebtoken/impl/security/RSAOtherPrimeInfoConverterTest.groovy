package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class RSAOtherPrimeInfoConverterTest {

    @Test
    void testApplyFromNull() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom(null)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = 'RSA JWK \'oth\' (Other Prime Info) element cannot be null.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testApplyFromWithoutMap() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom(42)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = 'RSA JWK \'oth\' (Other Prime Info) must contain map elements of ' +
                    'name/value pairs. Element type found: java.lang.Integer'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testApplyFromWithEmptyMap() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom([:])
            fail()
        } catch (MalformedKeyException expected) {
            String msg = 'RSA JWK \'oth\' (Other Prime Info) element map cannot be empty.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testApplyFromWithMalformedMap() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom(['r':2])
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Invalid JWK 'r' (Prime Factor) value <redacted>. Values must be either String or " +
                    "java.math.BigInteger instances. Value type found: java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }
}
