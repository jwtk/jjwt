package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PbeKey;
import io.jsonwebtoken.security.PbeKeyBuilder;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public class KeysBridge {

    // prevent instantiation
    private KeysBridge() {
    }

    public static PbeKeyBuilder<PbeKey> forPbe() {
        return new DefaultPbeKeyBuilder<>();
    }
}
