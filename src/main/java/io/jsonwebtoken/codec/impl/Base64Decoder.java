package io.jsonwebtoken.codec.impl;

import io.jsonwebtoken.codec.Decoder;
import io.jsonwebtoken.codec.DecodingException;
import io.jsonwebtoken.lang.Assert;

public class Base64Decoder extends Base64Support implements Decoder<String, byte[]> {

    public Base64Decoder() {
        super(Base64.DEFAULT);
    }

    Base64Decoder(Base64 base64) {
        super(base64);
    }

    @Override
    public byte[] decode(String s) throws DecodingException {
        Assert.notNull(s, "String argument cannot be null");
        return this.base64.decodeFast(s.toCharArray());
    }
}