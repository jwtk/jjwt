package io.jsonwebtoken.security;

import io.jsonwebtoken.JweHeader;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptionAlgorithmLocator {

    EncryptionAlgorithm getEncryptionAlgorithm(JweHeader jweHeader);
}
