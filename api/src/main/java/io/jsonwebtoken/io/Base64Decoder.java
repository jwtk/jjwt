package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Assert;

/**
 * @since 0.10.0
 */
class Base64Decoder extends Base64Support implements Decoder<String, byte[]> {

    Base64Decoder() {
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