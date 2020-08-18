package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricKeySignatureAlgorithm extends SignatureAlgorithm<SecretKey, SecretKey>, SymmetricKeyAlgorithm {
}
