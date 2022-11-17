package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Password;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

    // prevent instantiation
    private KeysBridge() {
    }

    public static Password forPassword(char[] password) {
        return new PasswordSpec(password);
    }
}
