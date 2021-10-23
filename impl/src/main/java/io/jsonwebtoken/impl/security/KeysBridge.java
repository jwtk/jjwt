package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PasswordKey;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

    // prevent instantiation
    private KeysBridge() {
    }

    public static PasswordKey forPassword(char[] password) {
        return new DefaultPasswordKey(password);
    }
}
