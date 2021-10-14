package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AeadAlgorithm;

import java.util.Collection;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.EncryptionAlgorithms implementation
public final class EncryptionAlgorithmsBridge {

    // prevent instantiation
    private EncryptionAlgorithmsBridge() {
    }

    //For parser implementation - do not expose outside the impl module:
    public static final Registry<String, AeadAlgorithm> REGISTRY;

    static {
        REGISTRY = new IdRegistry<>(Collections.of(
            (AeadAlgorithm) new HmacAesAeadAlgorithm(128),
            new HmacAesAeadAlgorithm(192),
            new HmacAesAeadAlgorithm(256),
            new GcmAesAeadAlgorithm(128),
            new GcmAesAeadAlgorithm(192),
            new GcmAesAeadAlgorithm(256)
        ));
    }

    public static Collection<AeadAlgorithm> values() {
        return REGISTRY.values();
    }

    public static AeadAlgorithm findById(String id) {
        return REGISTRY.apply(id);
    }

    public static AeadAlgorithm forId(String id) {
        AeadAlgorithm alg = findById(id);
        if (alg == null) {
            String msg = "Unrecognized JWA AeadAlgorithm identifier: " + id;
            throw new UnsupportedJwtException(msg);
        }
        return alg;
    }
}
