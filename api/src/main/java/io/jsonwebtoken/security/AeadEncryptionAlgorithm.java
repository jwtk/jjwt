package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AeadEncryptionAlgorithm<T, EK extends Key, DK extends Key, EReq extends AeadRequest<T, EK>, ERes extends AeadEncryptionResult, DReq extends AeadDecryptionRequest<T, DK>> extends EncryptionAlgorithm<T, EK, DK, EReq, ERes, DReq> {
}
