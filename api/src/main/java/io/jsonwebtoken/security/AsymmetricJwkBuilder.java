package io.jsonwebtoken.security;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

public interface AsymmetricJwkBuilder<K extends Key, J extends AsymmetricJwk<K>, T extends AsymmetricJwkBuilder<K, J, T>> extends JwkBuilder<K, J, T> {

    T setPublicKeyUse(String use);

    T setX509CertificateChain(List<X509Certificate> chain);

    T setX509Url(URI uri);

    T withX509KeyUse(boolean enable);

    T withX509Sha1Thumbprint(boolean enable);

    T withX509Sha256Thumbprint(boolean enable);
}
