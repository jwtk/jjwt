package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

import java.math.BigInteger;

public class BigIntegerUBytesConverter implements Converter<BigInteger, byte[]> {

    // Copied from Apache Commons Codec 1.14:
    // https://github.com/apache/commons-codec/blob/af7b94750e2178b8437d9812b28e36ac87a455f2/src/main/java/org/apache/commons/codec/binary/Base64.java#L746-L775
    @Override
    public byte[] applyTo(BigInteger bigInt) {
        Assert.notNull(bigInt, "BigInteger argument cannot be null.");
        final int bitlen = bigInt.bitLength();
        // round bitlen
        final int roundedBitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bitlen % 8) != 0) && (((bitlen / 8) + 1) == (roundedBitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bitlen % 8) == 0) {
            startSrc = 1;
            len--;
        }
        final int startDst = roundedBitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[roundedBitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

    @Override
    public BigInteger applyFrom(byte[] bytes) {
        return new BigInteger(1, bytes);
    }
}
