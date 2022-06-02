package io.jsonwebtoken.impl.security


import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class EcPrivateJwkFactoryTest {

    @Test
    void testDMissing() {
        def values = ['kty': 'EC', 'crv': 'P-256', 'x': BigInteger.ONE, 'y': BigInteger.ONE]
        try {
            def ctx = new DefaultJwkContext(DefaultEcPrivateJwk.FIELDS)
            ctx.putAll(values)
            new EcPrivateJwkFactory().createJwkFromValues(ctx)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'd' (ECC Private Key) value."
            assertEquals msg, expected.getMessage()
        }
    }
}
