package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SecretKeyAlgorithm extends KeyAlgorithm<SecretKey, SecretKey>, KeyBuilderSupplier<SecretKey, SecretKeyBuilder> {
}
