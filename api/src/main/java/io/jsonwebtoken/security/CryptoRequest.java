package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface CryptoRequest<T, K extends Key> extends SecurityRequest, PayloadSupplier<T>, KeySupplier<K> {
}
