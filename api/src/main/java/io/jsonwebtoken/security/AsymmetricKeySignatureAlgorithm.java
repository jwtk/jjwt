package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricKeySignatureAlgorithm<SK extends PrivateKey, VK extends PublicKey> extends SignatureAlgorithm<SK, VK>, AsymmetricKeyGenerator {
}
