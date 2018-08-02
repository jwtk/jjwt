package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AeadSymmetricEncryptionAlgorithm<T> extends
    SymmetricEncryptionAlgorithm<T, AeadRequest<T, SecretKey>, AeadIvEncryptionResult, AeadIvRequest<T, SecretKey>>,
    AeadEncryptionAlgorithm<T, SecretKey, SecretKey, AeadRequest<T, SecretKey>, AeadIvEncryptionResult, AeadIvRequest<T, SecretKey>>  {
}
