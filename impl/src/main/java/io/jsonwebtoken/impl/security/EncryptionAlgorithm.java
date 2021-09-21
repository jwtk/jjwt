package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.PayloadSupplier;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptionAlgorithm<T,
    EK extends Key, DK extends Key,
    EReq extends CryptoRequest<T, EK>, ERes extends PayloadSupplier<byte[]>,
    DReq extends CryptoRequest<byte[], DK>, DRes extends PayloadSupplier<T>> extends Identifiable {

    ERes encrypt(EReq request) throws CryptoException, KeyException;

    DRes decrypt(DReq request) throws CryptoException, KeyException;
}
