package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;

import java.net.URI;
import java.util.List;
import java.util.Set;

@SuppressWarnings("unchecked")
abstract class AbstractJwkBuilder<T extends JwkBuilder, K extends Jwk> implements JwkBuilder<T, K> {

    protected final K jwk;

    private final JwkValidator<K> validator;

    AbstractJwkBuilder(JwkValidator<K> validator) {
        Assert.notNull(validator, "validator cannot be null.");
        this.validator = validator;
        this.jwk = newJwk();
        Assert.notNull(this.jwk, "newJwk implementation cannot return a null instance.");
    }

    abstract K newJwk();

    public final K build() {
        validator.validate(this.jwk);
        return jwk;
    }

    @Override
    public T setUse(String use) {
        this.jwk.setUse(use);
        return (T)this;
    }

    @Override
    public T setOperations(Set<String> ops) {
        this.jwk.setOperations(ops);
        return (T)this;
    }

    @Override
    public T setAlgorithm(String alg) {
        this.jwk.setAlgorithm(alg);
        return (T)this;
    }

    @Override
    public T setId(String id) {
        this.jwk.setId(id);
        return (T)this;
    }

    @Override
    public T setX509Url(URI url) {
        this.jwk.setX509Url(url);
        return (T)this;
    }

    @Override
    public T setX509CertificateChain(List<String> chain) {
        this.jwk.setX509CertificateChain(chain);
        return (T)this;
    }

    @Override
    public T setX509CertificateSha1Thumbprint(String thumbprint) {
        this.jwk.setX509CertificateSha1Thumbprint(thumbprint);
        return (T)this;
    }

    @Override
    public T setX509CertificateSha256Thumbprint(String thumbprint) {
        this.jwk.setX509CertificateSha256Thumbprint(thumbprint);
        return (T)this;
    }
}
