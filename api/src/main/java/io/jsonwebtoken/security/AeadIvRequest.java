package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AeadIvRequest<T, K extends Key> extends IvRequest<T, K>, AeadDecryptionRequest<T, K> {
}
