package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.DynamicJwkBuilder;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperationPolicy;
import io.jsonwebtoken.security.MalformedKeySetException;

import java.security.Provider;
import java.util.Map;

public class DefaultJwkSetParser extends AbstractJwkParser<JwkSet> {

    private final Converter<JwkSet, Object> CONVERTER;

    public DefaultJwkSetParser(final Provider provider, Deserializer<Map<String, ?>> deserializer, final KeyOperationPolicy policy) {
        super(provider, deserializer, policy);
        @SuppressWarnings("unchecked") Class<Jwk<?>> clazz = (Class<Jwk<?>>) (Class<?>) Jwk.class;
        Supplier<DynamicJwkBuilder<?, ?>> supplier = new Supplier<DynamicJwkBuilder<?, ?>>() {
            @Override
            public DynamicJwkBuilder<?, ?> get() {
                return Jwks.builder().provider(provider).operationPolicy(policy);
            }
        };
        this.CONVERTER = new JwkSetConverter(new JwkConverter<>(clazz, supplier));
    }

    @Override
    protected Map<String, ?> deserialize(byte[] data) {
        try {
            return super.deserialize(data);
        } catch (Throwable t) {
            String msg = "Unable to deserialize content to a JWK Set: " + t.getMessage();
            throw new MalformedKeySetException(msg, t);
        }
    }

    @Override
    protected JwkSet convert(Map<String, ?> m) {
        return this.CONVERTER.applyFrom(m);
    }

}
