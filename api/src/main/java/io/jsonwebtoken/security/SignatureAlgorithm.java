package io.jsonwebtoken.security;

import io.jsonwebtoken.Named;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SignatureAlgorithm extends Named {

    byte[] sign(CryptoRequest<byte[], Key> request) throws SignatureException, KeyException;

    boolean verify(VerifySignatureRequest request) throws SignatureException, KeyException;
}
