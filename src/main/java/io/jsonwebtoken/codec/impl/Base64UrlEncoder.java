package io.jsonwebtoken.codec.impl;

/**
 * @since 0.10.0
 */
public class Base64UrlEncoder extends Base64Encoder {

    public Base64UrlEncoder() {
        super(Base64.URL_SAFE);
    }
}
