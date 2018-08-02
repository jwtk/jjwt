package io.jsonwebtoken.impl.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptKeyRequest {

    SecretKey getKey();

}
