package io.jsonwebtoken.impl.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class KeyEncryptionMode extends RandomEncryptedKeyMode {

    @Override
    public byte[] encryptKey(EncryptKeyRequest request) {
        throw new UnsupportedOperationException("Not Yet Implemented.");
    }
}
