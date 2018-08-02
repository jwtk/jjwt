package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface VerifySignatureRequest extends CryptoRequest<byte[], Key> {

    byte[] getSignature();
}
