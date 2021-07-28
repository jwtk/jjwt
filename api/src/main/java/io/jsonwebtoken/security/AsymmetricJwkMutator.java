package io.jsonwebtoken.security;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

public interface AsymmetricJwkMutator<T extends AsymmetricJwkMutator<T>> {

    T setPublicKeyUse(String use);

    T setX509CertificateChain(List<X509Certificate> chain);

    T setX509Url(URI uri);

    T withX509KeyUse(boolean enable);

    T withX509Sha1Thumbprint(boolean enable);

    T withX509Sha256Thumbprint(boolean enable);
}
