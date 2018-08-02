package io.jsonwebtoken.security;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwk<T extends Jwk> extends Map<String, Object>, JwkMutator<T> {

    String getType();

    String getUse();

    Set<String> getOperations();

    String getAlgorithm();

    String getId();

    URI getX509Url();

    List<String> getX509CertficateChain();

    String getX509CertificateSha1Thumbprint();

    String getX509CertificateSha256Thumbprint();
}
