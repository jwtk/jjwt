package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.KeyAlgorithm;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.KeyAlgorithms implementation
public final class KeyAlgorithmsBridge {

    // prevent instantiation
    private KeyAlgorithmsBridge() {
    }

    private static final String RSA1_5_ID = "RSA1_5";
    private static final String RSA1_5_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String RSA_OAEP_ID = "RSA-OAEP";
    private static final String RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String RSA_OAEP_256_ID = "RSA-OAEP-256";
    private static final String RSA_OAEP_256_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final AlgorithmParameterSpec RSA_OAEP_256_SPEC =
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    //For parser implementation - do not expose outside the impl module
    public static final Registry<String, KeyAlgorithm<?, ?>> REGISTRY;

    static {
        REGISTRY = new IdRegistry<>(Collections.<KeyAlgorithm<?, ?>>of(
            new DirectKeyAlgorithm(),
            new AesWrapKeyAlgorithm(128),
            new AesWrapKeyAlgorithm(192),
            new AesWrapKeyAlgorithm(256),
            new AesGcmKeyAlgorithm(128),
            new AesGcmKeyAlgorithm(192),
            new AesGcmKeyAlgorithm(256),
            new Pbes2HsAkwAlgorithm(128),
            new Pbes2HsAkwAlgorithm(192),
            new Pbes2HsAkwAlgorithm(256),
            new DefaultRsaKeyAlgorithm<>(RSA1_5_ID, RSA1_5_TRANSFORMATION),
            new DefaultRsaKeyAlgorithm<>(RSA_OAEP_ID, RSA_OAEP_TRANSFORMATION),
            new DefaultRsaKeyAlgorithm<>(RSA_OAEP_256_ID, RSA_OAEP_256_TRANSFORMATION, RSA_OAEP_256_SPEC)
        ));
    }

    public static Collection<KeyAlgorithm<?, ?>> values() {
        return REGISTRY.values();
    }

    public static KeyAlgorithm<?, ?> findById(String id) {
        return REGISTRY.apply(id);
    }

    public static KeyAlgorithm<?, ?> forId(String id) {
        KeyAlgorithm<?, ?> instance = findById(id);
        if (instance == null) {
            String msg = "Unrecognized JWA KeyAlgorithm identifier: " + id;
            throw new UnsupportedJwtException(msg);
        }
        return instance;
    }
}
