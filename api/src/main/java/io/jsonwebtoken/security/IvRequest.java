package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface IvRequest<T, K extends Key> extends CryptoRequest<T, K>, InitializationVectorSource {
}
