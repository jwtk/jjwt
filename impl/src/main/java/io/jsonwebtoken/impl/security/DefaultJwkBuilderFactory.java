package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.EcJwkBuilderFactory;
import io.jsonwebtoken.security.JwkBuilderFactory;
import io.jsonwebtoken.security.SymmetricJwkBuilder;

public final class DefaultJwkBuilderFactory implements JwkBuilderFactory {

    @Override
    public EcJwkBuilderFactory ellipticCurve() {
        return new DefaultEcJwkBuilderFactory();
    }

    @Override
    public SymmetricJwkBuilder symmetric() {
        return new DefaultSymmetricJwkBuilder();
    }
}
