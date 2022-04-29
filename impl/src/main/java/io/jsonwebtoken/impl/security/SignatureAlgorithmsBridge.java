package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.SignatureAlgorithm;

import java.util.Collection;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.SignatureAlgorithms implementation
public final class SignatureAlgorithmsBridge {

    //prevent instantiation
    private SignatureAlgorithmsBridge() {
    }

    //For parser implementation - do not expose outside the impl module
    public static final Registry<String, SignatureAlgorithm<?, ?>> REGISTRY;

    static {
        //noinspection RedundantTypeArguments
        REGISTRY = new IdRegistry<>(Collections.<SignatureAlgorithm<?, ?>>of(
            new NoneSignatureAlgorithm(),
            new MacSignatureAlgorithm(256),
            new MacSignatureAlgorithm(384),
            new MacSignatureAlgorithm(512),
            new DefaultRsaSignatureAlgorithm<>(256, 2048),
            new DefaultRsaSignatureAlgorithm<>(384, 3072),
            new DefaultRsaSignatureAlgorithm<>(512, 4096),
            new DefaultRsaSignatureAlgorithm<>(256, 2048, 256),
            new DefaultRsaSignatureAlgorithm<>(384, 3072, 384),
            new DefaultRsaSignatureAlgorithm<>(512, 4096, 512),
            new DefaultEllipticCurveSignatureAlgorithm<>(256),
            new DefaultEllipticCurveSignatureAlgorithm<>(384),
            new DefaultEllipticCurveSignatureAlgorithm<>(521)
        ));
    }

    public static Collection<SignatureAlgorithm<?, ?>> values() {
        return REGISTRY.values();
    }

    public static SignatureAlgorithm<?, ?> findById(String id) {
        return REGISTRY.apply(id);
    }

    public static SignatureAlgorithm<?, ?> forId(String id) {
        SignatureAlgorithm<?, ?> instance = findById(id);
        if (instance == null) {
            String msg = "Unrecognized JWA SignatureAlgorithm identifier: " + id;
            throw new UnsupportedJwtException(msg);
        }
        return instance;
    }
}
