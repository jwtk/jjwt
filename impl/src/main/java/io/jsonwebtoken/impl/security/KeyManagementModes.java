package io.jsonwebtoken.impl.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class KeyManagementModes {

    private KeyManagementModes(){}

    public static KeyManagementMode direct(SecretKey secretKey) {
        return new DirectEncryptionMode(secretKey);
    }
}
