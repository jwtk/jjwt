package io.jsonwebtoken.security;

import io.jsonwebtoken.Named;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptionAlgorithm<T, EK extends Key, DK extends Key, EReq extends CryptoRequest<T, EK>, ERes extends EncryptionResult, DReq extends CryptoRequest<T, DK>> extends Named {

    ERes encrypt(EReq request) throws CryptoException, KeyException;

    byte[] decrypt(DReq request) throws CryptoException, KeyException;
}
