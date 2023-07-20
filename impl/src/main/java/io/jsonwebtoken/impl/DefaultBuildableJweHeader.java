package io.jsonwebtoken.impl;

import io.jsonwebtoken.MutableJweHeader;
import io.jsonwebtoken.security.X509Builder;

/**
 * @param <T> return type for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultBuildableJweHeader<T extends MutableJweHeader<T> & X509Builder<T>>
        extends DefaultMutableJweHeader<T> implements X509Builder<T> {

    public DefaultBuildableJweHeader() {
        super();
    }

    public DefaultBuildableJweHeader(DefaultMutableJweHeader<?> src) {
        super(src);
    }

    @Override
    public T withX509Sha1Thumbprint(boolean enable) {
        this.x509.withX509Sha1Thumbprint(enable);
        return self();
    }

    @Override
    public T withX509Sha256Thumbprint(boolean enable) {
        this.x509.withX509Sha256Thumbprint(enable);
        return self();
    }
}
