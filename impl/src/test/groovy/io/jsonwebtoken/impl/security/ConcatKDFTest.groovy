package io.jsonwebtoken.impl.security

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class ConcatKDFTest {

    ConcatKDF CONCAT_KDF = EcdhKeyAlgorithm.CONCAT_KDF

    private byte[] Z

    @Before
    void setUp() {
        Z = new byte[16]
        Randoms.secureRandom().nextBytes(Z)
    }

    @Test
    void testNonPositiveBitLength() {
        try {
            CONCAT_KDF.deriveKey(Z, 0, null)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'derivedKeyBitLength must be a positive number.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testDerivedKeyBitLengthBiggerThanJdkMax() {
        byte[] Z = new byte[16]
        long bitLength = Long.valueOf(Integer.MAX_VALUE) * 8L + 8L // one byte more than java byte arrays can handle
        try {
            CONCAT_KDF.deriveKey(Z, bitLength, null)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'derivedKeyBitLength may not exceed 17179869176 bits (2147483647 bytes). ' +
                    'Specified size: 17179869184 bits (2147483648 bytes).'
            assertEquals msg, expected.getMessage()
        }
    }
}
