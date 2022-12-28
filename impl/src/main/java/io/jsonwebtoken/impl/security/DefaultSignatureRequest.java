package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.SignatureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultSignatureRequest<K extends Key> extends DefaultSecureRequest<byte[], K> implements SignatureRequest<K> {

    public DefaultSignatureRequest(byte[] data, Provider provider, SecureRandom secureRandom, K key) {
        super(data, provider, secureRandom, key);
    }
}
