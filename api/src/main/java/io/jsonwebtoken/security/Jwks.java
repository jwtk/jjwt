package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Classes;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class Jwks {

    public static <T extends JwkBuilderFactory> T builder() {
        return Classes.newInstance("io.jsonwebtoken.impl.security.DefaultJwkBuilderFactory");
    }

}
