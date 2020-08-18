package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface VerifySignatureRequest<K extends Key> extends SignatureRequest<K> {

    byte[] getSignature();
}
