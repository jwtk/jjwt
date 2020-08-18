package io.jsonwebtoken.impl.security

import org.junit.Test
import static org.junit.Assert.*

class CryptoAlgorithmTest {

    @Test
    void testEqualsSameInstance() {
        def alg = new TestCryptoAlgorithm('test', 'test')
        assertEquals alg, alg
    }

    @Test
    void testEqualsSameNameAndJcaName() {
        def alg1 = new TestCryptoAlgorithm('test', 'test')
        def alg2 = new TestCryptoAlgorithm('test', 'test')
        assertEquals alg1, alg2
    }

    @Test
    void testEqualsSameNameButDifferentJcaName() {
        def alg1 = new TestCryptoAlgorithm('test', 'test1')
        def alg2 = new TestCryptoAlgorithm('test', 'test2')
        assertNotEquals alg1, alg2
    }

    @Test
    void testEqualsOtherType() {
        assertNotEquals new TestCryptoAlgorithm('test', 'test'), new Object()
    }

    @Test
    void testToString() {
        assertEquals 'test', new TestCryptoAlgorithm('test', 'whatever').toString()
    }

    @Test
    void testHashCode() {
        int hash = 7
        hash = 31 * hash + 'name'.hashCode()
        hash = 31 * hash + 'jcaName'.hashCode()
        assertEquals hash, new TestCryptoAlgorithm('name', 'jcaName').hashCode()
    }

    class TestCryptoAlgorithm extends CryptoAlgorithm {
        TestCryptoAlgorithm(String id, String jcaName) {
            super(id, jcaName)
        }
    }
}
