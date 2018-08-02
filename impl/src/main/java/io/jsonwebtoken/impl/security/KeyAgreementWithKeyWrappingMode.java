package io.jsonwebtoken.impl.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class KeyAgreementWithKeyWrappingMode extends RandomEncryptedKeyMode {

    @Override
    public byte[] encryptKey(EncryptKeyRequest request) {
        throw new UnsupportedOperationException("Not Yet Implemented");
    }
}
