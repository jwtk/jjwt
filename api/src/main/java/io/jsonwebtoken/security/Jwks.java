package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class Jwks {

    private static final String BUILDER_CLASS_NAME = "io.jsonwebtoken.impl.security.DefaultJwkBuilder";
    private static final Class<?>[] KEY_ARGS = new Class[]{Key.class};

    public static SecretJwkBuilder builder(SecretKey key) {
        return Classes.newInstance(BUILDER_CLASS_NAME, KEY_ARGS, key);
    }

    public static RsaPublicJwkBuilder<?> builder(RSAPublicKey key) {
        return Classes.newInstance(BUILDER_CLASS_NAME, KEY_ARGS, key);
    }

    public static EcPublicJwkBuilder<?> builder(ECPublicKey key) {
        return Classes.newInstance(BUILDER_CLASS_NAME, KEY_ARGS, key);
    }

    public static RsaPrivateJwkBuilder<?> builder(RSAPrivateKey key) {
        return Classes.newInstance(BUILDER_CLASS_NAME, KEY_ARGS, key);
    }

    public static EcPrivateJwkBuilder<?> builder(ECPrivateKey key) {
        return Classes.newInstance(BUILDER_CLASS_NAME, KEY_ARGS, key);
    }

    public static Jwk<?, ?> forValues(Map<String, ?> values) {
        JwkBuilder<?, ?, ?> builder = Classes.newInstance(BUILDER_CLASS_NAME);
        return builder.putAll(values).build();
    }
}
