package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SignatureRequest<K extends Key> extends CryptoRequest<byte[], K> {
}
