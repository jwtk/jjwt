package io.jsonwebtoken.codec.impl;

/**
 * @since 0.10.0
 */
public class Base64UrlDecoder extends Base64Decoder {

    public Base64UrlDecoder() {
        super(Base64.URL_SAFE);
    }
}
