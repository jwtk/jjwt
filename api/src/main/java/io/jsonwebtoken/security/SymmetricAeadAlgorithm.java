package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricAeadAlgorithm extends Identifiable, SecretKeyGenerator {

    AeadResult encrypt(SymmetricAeadRequest request) throws CryptoException, KeyException;

    PayloadSupplier<byte[]> decrypt(SymmetricAeadDecryptionRequest request) throws CryptoException, KeyException;
}
