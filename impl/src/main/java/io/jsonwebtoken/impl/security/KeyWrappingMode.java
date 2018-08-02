package io.jsonwebtoken.impl.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class KeyWrappingMode extends RandomEncryptedKeyMode {

    @Override
    public byte[] encryptKey(EncryptKeyRequest request) {
        throw new UnsupportedOperationException("Not Yet Implemented");
    }
}
