package io.jsonwebtoken.impl.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DirectKeyAgreementMode implements KeyManagementMode {

    @Override
    public SecretKey getKey(GetKeyRequest request) {
        throw new UnsupportedOperationException("Not Yet Implemented");
    }
}
