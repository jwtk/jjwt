package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface RsaSignatureAlgorithm<SK extends RSAKey & PrivateKey, VK extends RSAKey & PublicKey> extends AsymmetricKeySignatureAlgorithm<SK, VK> {
}
