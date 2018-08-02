package io.jsonwebtoken.security;

import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkMutator<T extends JwkMutator> {

    T setUse(String use);

    T setOperations(Set<String> ops);

    T setAlgorithm(String alg);

    T setId(String id);

    T setX509Url(URI uri);

    T setX509CertificateChain(List<String> chain);

    T setX509CertificateSha1Thumbprint(String thumbprint);

    T setX509CertificateSha256Thumbprint(String thumbprint);
}
