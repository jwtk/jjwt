package io.jsonwebtoken.security;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

public interface AsymmetricJwk<K extends Key> extends Jwk<K> {

    String getPublicKeyUse();

    URI getX509Url();

    List<X509Certificate> getX509CertificateChain();

    byte[] getX509CertificateSha1Thumbprint();

    byte[] getX509CertificateSha256Thumbprint();
}
