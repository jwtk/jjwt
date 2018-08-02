package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptionAlgorithm;
import io.jsonwebtoken.security.SymmetricEncryptionAlgorithm;

import javax.crypto.SecretKey;

/**
 * Abstract class that implements {@link KeyManagementMode#getKey(GetKeyRequest) getKey} and leaves
 * {@link EncryptedKeyManagementMode#encryptKey(EncryptKeyRequest)} to subclasses.
 *
 * @since JJWT_RELEASE_VERSION
 */
public abstract class RandomEncryptedKeyMode implements EncryptedKeyManagementMode {

    @Override
    public SecretKey getKey(GetKeyRequest request) {

        Assert.notNull(request, "GetKeyRequest cannot be null.");

        EncryptionAlgorithm alg = Assert.notNull(request.getEncryptionAlgorithm(),
            "GetKeyRequest encryptionAlgorithm cannot be null.");

        if (!(alg instanceof SymmetricEncryptionAlgorithm)) {
            String msg = "The standard JWE Encrypted Key Management Modes only support symmetric encryption " +
                "algorithms.  The specified GetKeyRequest encryptionAlgorithm is an instance of " +
                alg.getClass().getName() + " which does not implement " +
                SymmetricEncryptionAlgorithm.class.getName() + ".  Either specify a JWE-standard symmetric " +
                "encryption algorithm or create a custom (non-standard) EncryptedKeyManagementMode implementation.";
            throw new IllegalArgumentException(msg);
        }

        SymmetricEncryptionAlgorithm salg = (SymmetricEncryptionAlgorithm) alg;

        return salg.generateKey();
    }
}
