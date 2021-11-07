package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyBuilder<K extends SecretKey, B extends KeyBuilder<K, B>> extends SecurityBuilder<K, B> {
}
