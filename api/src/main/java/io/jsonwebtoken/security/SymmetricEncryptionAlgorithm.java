package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricEncryptionAlgorithm<T, EReq extends CryptoRequest<T, SecretKey>, ERes extends IvEncryptionResult, DReq extends IvRequest<T, SecretKey>> extends EncryptionAlgorithm<T, SecretKey, SecretKey, EReq, ERes, DReq>, SymmetricKeyAlgorithm {
}
