package io.jsonwebtoken.impl;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.security.AbstractAsymmetricJwk;
import io.jsonwebtoken.security.X509Mutator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public class AbstractX509Context<T extends X509Mutator<T>> extends FieldMap implements X509Context<T> {

    public AbstractX509Context(Set<Field<?>> fieldSet) {
        super(fieldSet);
    }

    @SuppressWarnings("unchecked")
    protected T self() {
        return (T) this;
    }

    @Override
    public URI getX509Url() {
        return get(AbstractAsymmetricJwk.X5U);
    }

    @Override
    public T setX509Url(URI uri) {
        put(AbstractAsymmetricJwk.X5U, uri);
        return self();
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(AbstractAsymmetricJwk.X5C);
    }

    @Override
    public T setX509CertificateChain(List<X509Certificate> chain) {
        put(AbstractAsymmetricJwk.X5C, chain);
        return self();
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(AbstractAsymmetricJwk.X5T);
    }

    @Override
    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T, thumbprint);
        return self();
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(AbstractAsymmetricJwk.X5T_S256);
    }

    @Override
    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T_S256, thumbprint);
        return self();
    }
}
