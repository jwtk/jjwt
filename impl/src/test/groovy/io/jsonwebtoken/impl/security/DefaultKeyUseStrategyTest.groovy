package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

class DefaultKeyUseStrategyTest {

    final KeyUseStrategy strat = DefaultKeyUseStrategy.INSTANCE

    private static KeyUsage usage(int trueIndex) {
        boolean[] usage = new boolean[9]
        usage[trueIndex] = true
        return new KeyUsage(new TestX509Certificate(keyUsage: usage))
    }

    @Test
    void testKeyEncipherment() {
        assertEquals 'enc', strat.toJwkValue(usage(2))
    }

    @Test
    void testDataEncipherment() {
        assertEquals 'enc', strat.toJwkValue(usage(3))
    }

    @Test
    void testKeyAgreement() {
        assertEquals 'enc', strat.toJwkValue(usage(4))
    }

    @Test
    void testDigitalSignature() {
        assertEquals 'sig', strat.toJwkValue(usage(0))
    }

    @Test
    void testNonRepudiation() {
        assertEquals 'sig', strat.toJwkValue(usage(1))
    }

    @Test
    void testKeyCertSign() {
        assertEquals 'sig', strat.toJwkValue(usage(5))
    }

    @Test
    void testCRLSign() {
        assertEquals 'sig', strat.toJwkValue(usage(6))
    }

    @Test
    void testEncipherOnly() {
        assertNull strat.toJwkValue(usage(7))
    }

    @Test
    void testDecipherOnly() {
        assertNull strat.toJwkValue(usage(8))
    }
}
