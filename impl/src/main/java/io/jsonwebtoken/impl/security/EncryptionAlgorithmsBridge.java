package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;

import java.util.Collection;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.EncryptionAlgorithms implementation
public class EncryptionAlgorithmsBridge {

    // prevent instantiation
    private EncryptionAlgorithmsBridge() {
    }

    //For parser implementation - do not expose outside the impl module:
    public static final Registry<String, SymmetricAeadAlgorithm> REGISTRY;

    static {
        REGISTRY = new IdRegistry<>(Collections.of(
            (SymmetricAeadAlgorithm) new HmacAesAeadAlgorithm(128),
            new HmacAesAeadAlgorithm(192),
            new HmacAesAeadAlgorithm(256),
            new GcmAesAeadAlgorithm(128),
            new GcmAesAeadAlgorithm(192),
            new GcmAesAeadAlgorithm(256)
        ));
    }

    public static Collection<SymmetricAeadAlgorithm> values() {
        return REGISTRY.values();
    }

    public static SymmetricAeadAlgorithm findById(String id) {
        return REGISTRY.apply(id);
    }

    public static SymmetricAeadAlgorithm forId(String id) {
        SymmetricAeadAlgorithm alg = findById(id);
        if (alg == null) {
            String msg = "Unrecognized JWA EncryptionAlgorithm identifier: " + id;
            throw new UnsupportedJwtException(msg);
        }
        return alg;
    }
}
