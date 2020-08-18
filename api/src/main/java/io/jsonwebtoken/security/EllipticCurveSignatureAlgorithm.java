package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EllipticCurveSignatureAlgorithm<SK extends ECKey & PrivateKey, VK extends ECKey & PublicKey> extends AsymmetricKeySignatureAlgorithm<SK, VK> {
}
