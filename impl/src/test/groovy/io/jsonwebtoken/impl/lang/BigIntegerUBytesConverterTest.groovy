package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.*

class BigIntegerUBytesConverterTest {

    private BigIntegerUBytesConverter CONVERTER = Converters.BIGINT_UBYTES as BigIntegerUBytesConverter

    @Test
    void testNegative() {
        try {
            CONVERTER.applyTo(BigInteger.valueOf(-1))
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals BigIntegerUBytesConverter.NEGATIVE_MSG, expected.getMessage()
        }
    }

    @Test
    void testZero() {
        byte[] result = CONVERTER.applyTo(BigInteger.ZERO)
        assertEquals 1, result.length
        assertTrue result[0] == 0x00 as byte
    }

    @Test
    void testStripSignByte() {
        BigInteger val = BigInteger.valueOf(128)
        byte[] bytes = val.toByteArray()
        byte[] result = CONVERTER.applyTo(val)
        assertEquals bytes.length - 1, result.length
    }

    /**
     * Asserts https://www.rfc-editor.org/rfc/rfc7518.html#section-2, 'Base64urlUInt' definition, last sentence:
     * <pre>Zero is represented as BASE64URL(single zero-valued octet), which is "AA".</pre>
     */
    @Test
    void testZeroProducesAABase64Url() {
        assertEquals 'AA', Converters.BIGINT.applyTo(BigInteger.ZERO)
    }
}
