package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecretJwkBuilder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.Provider;
import java.util.Map;
import java.util.Set;

abstract class AbstractJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>> implements JwkBuilder<K, J, T> {

    protected final JwkContext<K> jwkContext;
    protected final JwkFactory<K, J> jwkFactory;

    @SuppressWarnings("unchecked")
    protected AbstractJwkBuilder(JwkContext<K> jwkContext) {
        this.jwkContext = Assert.notNull(jwkContext, "JwkContext cannot be null.");
        this.jwkFactory = (JwkFactory<K, J>) DispatchingJwkFactory.DEFAULT_INSTANCE;
    }

    @Override
    public T setProvider(Provider provider) {
        Assert.notNull(provider, "Provider cannot be null.");
        jwkContext.setProvider(provider);
        return tthis();
    }

    @Override
    public T put(String name, Object value) {
        jwkContext.put(name, value);
        return tthis();
    }

    @Override
    public T putAll(Map<String, ?> values) {
        jwkContext.putAll(values);
        return tthis();
    }

    @Override
    public T setAlgorithm(String alg) {
        Assert.hasText(alg, "Algorithm cannot be null or empty.");
        jwkContext.setAlgorithm(alg);
        return tthis();
    }

    @Override
    public T setId(String id) {
        Assert.hasText(id, "Id cannot be null or empty.");
        jwkContext.setId(id);
        return tthis();
    }

    @Override
    public T setOperations(Set<String> ops) {
        Assert.notEmpty(ops, "Operations cannot be null or empty.");
        jwkContext.setOperations(ops);
        return tthis();
    }

    @SuppressWarnings("unchecked")
    protected final T tthis() {
        return (T) this;
    }

    @Override
    public J build() {

        assert this.jwkContext != null; //should always exist as there isn't a way to set it outside the constructor

        K key = this.jwkContext.getKey();
        if (key == null && this.jwkContext.isEmpty()) {
            String msg = "A " + Key.class.getName() + " or one or more name/value pairs must be provided to create a JWK.";
            throw new IllegalStateException(msg);
        }
        try {
            return jwkFactory.createJwk(this.jwkContext);
        } catch (IllegalArgumentException iae) {
            //if we get an IAE, it means the builder state wasn't configured enough in order to create
            String msg = "Unable to create JWK: " + iae.getMessage();
            throw new MalformedKeyException(msg, iae);
        }
    }

    static class DefaultSecretJwkBuilder extends AbstractJwkBuilder<SecretKey, SecretJwk, SecretJwkBuilder>
        implements SecretJwkBuilder {
        public DefaultSecretJwkBuilder(JwkContext<?> ctx, SecretKey key) {
            super(new DefaultJwkContext<>(DefaultSecretJwk.FIELDS, ctx, key));
        }
    }
}
