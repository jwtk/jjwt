package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.AsymmetricJwk;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

abstract class AbstractAsymmetricJwk<K extends Key> extends AbstractJwk<K> implements AsymmetricJwk<K> {

    static final String PUBLIC_KEY_USE = "use";
    static final String X509_URL = "x5u";
    static final String X509_CERT_CHAIN = "x5c";
    static final String X509_SHA1_THUMBPRINT = "x5t";
    static final String X509_SHA256_THUMBPRINT = "x5t#S256";

    AbstractAsymmetricJwk(JwkContext<K> ctx) {
        super(ctx);
    }

    @Override
    public String getPublicKeyUse() {
        return this.context.getPublicKeyUse();
    }

    @Override
    public URI getX509Url() {
        return this.context.getX509Url();
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return this.context.getX509CertificateChain();
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return this.context.getX509CertificateSha1Thumbprint();
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return this.context.getX509CertificateSha256Thumbprint();
    }

}
