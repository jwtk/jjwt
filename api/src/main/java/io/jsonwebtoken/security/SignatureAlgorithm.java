package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SignatureAlgorithm<S extends Key, V extends Key> extends Identifiable {

    byte[] sign(SignatureRequest<S> request) throws SecurityException;

    boolean verify(VerifySignatureRequest<V> request) throws SecurityException;
}
