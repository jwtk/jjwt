package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class RequiredBitLengthConverter implements Converter<byte[], Object> {

    private final Converter<byte[], Object> converter;

    private final int bitLength;
    private final boolean exact;

    public RequiredBitLengthConverter(Converter<byte[], Object> converter, int bitLength) {
        this(converter, bitLength, true);
    }

    public RequiredBitLengthConverter(Converter<byte[], Object> converter, int bitLength, boolean exact) {
        this.converter = Assert.notNull(converter, "Converter cannot be null.");
        this.bitLength = Assert.gt(bitLength, 0, "bitLength must be greater than 0");
        this.exact = exact;
    }

    private byte[] assertLength(byte[] bytes) {
        long len = Bytes.bitLength(bytes);
        if (exact && len != this.bitLength) {
            String msg = "Byte array must be exactly " + Bytes.bitsMsg(this.bitLength) + ". Found " + Bytes.bitsMsg(len);
            throw new IllegalArgumentException(msg);
        } else if (len < this.bitLength) {
            String msg = "Byte array must be at least " + Bytes.bitsMsg(this.bitLength) + ". Found " + Bytes.bitsMsg(len);
            throw new IllegalArgumentException(msg);
        }
        return bytes;
    }

    @Override
    public Object applyTo(byte[] bytes) {
        assertLength(bytes);
        return this.converter.applyTo(bytes);
    }

    @Override
    public byte[] applyFrom(Object o) {
        byte[] result = this.converter.applyFrom(o);
        return assertLength(result);
    }
}
