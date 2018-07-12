package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
class Base64UrlEncoder extends Base64Encoder {

    Base64UrlEncoder() {
        super(Base64.URL_SAFE);
    }
}
