package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricAeadAlgorithm extends Identifiable, SecretKeyGenerator {

    AeadResult encrypt(SymmetricAeadRequest request) throws SecurityException;

    PayloadSupplier<byte[]> decrypt(SymmetricAeadDecryptionRequest request) throws SecurityException;
}
