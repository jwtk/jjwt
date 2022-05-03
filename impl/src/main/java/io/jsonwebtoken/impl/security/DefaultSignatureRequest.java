package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.SignatureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultSignatureRequest<K extends Key> extends DefaultCryptoRequest<K> implements SignatureRequest<K> {

    public DefaultSignatureRequest(Provider provider, SecureRandom secureRandom, byte[] data, K key) {
        super(provider, secureRandom, data, key);
    }
}
