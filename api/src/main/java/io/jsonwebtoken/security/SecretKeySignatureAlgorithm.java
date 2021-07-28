package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SecretKeySignatureAlgorithm extends SignatureAlgorithm<SecretKey, SecretKey>, SecretKeyGenerator {
}
