package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.EcJwkBuilderFactory;
import io.jsonwebtoken.security.PrivateEcJwkBuilder;
import io.jsonwebtoken.security.PublicEcJwkBuilder;

final class DefaultEcJwkBuilderFactory implements EcJwkBuilderFactory {

    @Override
    public PublicEcJwkBuilder publicKey() {
        return new DefaultPublicEcJwkBuilder();
    }

    @Override
    public PrivateEcJwkBuilder privateKey() {
        return new DefaultPrivateEcJwkBuilder();
    }
}
