package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

import java.math.BigInteger;

public class BigIntegerUBytesConverter implements Converter<BigInteger, byte[]> {

    private static final String NEGATIVE_MSG =
        "JWA Base64urlUInt values MUST be >= 0 (non-negative) per the " +
            "[JWA RFC 7518, Section 2](https://datatracker.ietf.org/doc/html/rfc7518#section-2) " +
            "'Base64urlUInt' definition.";

    @Override
    public byte[] applyTo(BigInteger bigInt) {
        Assert.notNull(bigInt, "BigInteger argument cannot be null.");
        if (BigInteger.ZERO.compareTo(bigInt) > 0) {
            throw new IllegalArgumentException(NEGATIVE_MSG);
        }

        final int bitLen = bigInt.bitLength();
        final byte[] bytes = bigInt.toByteArray();
        // round bitLen. This gives the minimal number of bytes necessary to represent an unsigned byte array:
        final int unsignedByteLen = Math.max(1, (bitLen + 7) / Byte.SIZE);

        if (bytes.length == unsignedByteLen) { // already in the form we need
            return bytes;
        }
        //otherwise, we need to strip the sign byte (start copying at index 1 instead of 0):
        byte[] ubytes = new byte[unsignedByteLen];
        System.arraycopy(bytes, 1, ubytes, 0, unsignedByteLen);
        return ubytes;
    }

    @Override
    public BigInteger applyFrom(byte[] bytes) {
        return new BigInteger(1, bytes);
    }
}
