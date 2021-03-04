package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricAeadAlgorithm extends Identifiable, SymmetricKeyAlgorithm {

    SymmetricAeadEncryptionResult encrypt(SymmetricAeadRequest request) throws CryptoException, KeyException;

    PayloadSupplier<byte[]> decrypt(SymmetricAeadDecryptionRequest request) throws CryptoException, KeyException;
}
