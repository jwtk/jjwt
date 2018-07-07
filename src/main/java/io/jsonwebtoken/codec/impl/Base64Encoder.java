package io.jsonwebtoken.codec.impl;

import io.jsonwebtoken.codec.Encoder;
import io.jsonwebtoken.codec.EncodingException;
import io.jsonwebtoken.lang.Assert;

public class Base64Encoder extends Base64Support implements Encoder<byte[], String> {

    public Base64Encoder() {
        super(Base64.DEFAULT);
    }

    Base64Encoder(Base64 base64) {
        super(base64);
    }

    @Override
    public String encode(byte[] bytes) throws EncodingException {
        Assert.notNull(bytes, "byte array argument cannot be null");
        return this.base64.encodeToString(bytes, false);
    }
}
