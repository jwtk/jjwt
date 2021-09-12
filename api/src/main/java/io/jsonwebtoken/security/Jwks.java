package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Classes;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class Jwks {

    private static final String CNAME = "io.jsonwebtoken.impl.security.DefaultProtoJwkBuilder";

    public static ProtoJwkBuilder<?, ?, ?> builder() {
        return Classes.newInstance(CNAME);
    }
}
