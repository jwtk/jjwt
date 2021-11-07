package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * A {@link KeyBuilder} that creates new secure-random {@link SecretKey}s with a length sufficient to be used by
 * the security algorithm that produced this builder.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface SecretKeyBuilder extends KeyBuilder<SecretKey, SecretKeyBuilder> {
}
