package io.jsonwebtoken.security;

import io.jsonwebtoken.JweHeader;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyRequest<T, K extends Key> extends CryptoRequest<T, K> {

    SymmetricAeadAlgorithm getEncryptionAlgorithm();

    JweHeader getHeader();
}
