package io.jsonwebtoken.security;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

public interface AsymmetricJwk<V, K extends Key> extends Jwk<V, K> {

    String getUse();

    URI getX509Url();

    List<X509Certificate> getX509CertificateChain();

    byte[] getX509CertificateSha1Thumbprint();

    byte[] getX509CertificateSha256Thumbprint();
}
