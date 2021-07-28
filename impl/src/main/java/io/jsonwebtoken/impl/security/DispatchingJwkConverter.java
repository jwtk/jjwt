package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.jsonwebtoken.impl.security.AbstractJwkConverter.*;

public class DispatchingJwkConverter implements Converter<Key, Map<String,?>> {

    private final Map<String, JwkConverter<?>> converters = new HashMap<>();

    @SuppressWarnings("rawtypes")
    public DispatchingJwkConverter() {
        this(Collections.<JwkConverter<?>>of(
            new SymmetricJwkConverter(),
            new EcJwkConverter(),
            new RsaJwkConverter()));
    }

    public DispatchingJwkConverter(List<JwkConverter<?>> converters) {
        Assert.notEmpty(converters, "Converters cannot be null or empty.");
        for (JwkConverter<?> converter : converters) {
            this.converters.put(converter.getId(), converter);
        }
    }

    private JwkConverter<?> getConverter(String kty) {
        JwkConverter<?> converter = converters.get(kty);
        if (converter == null) {
            String msg = "Unrecognized JWK kty (key type) value: " + kty;
            throw new UnsupportedKeyException(msg);
        }
        return converter;
    }

    @Override
    public Map<String, ?> applyTo(Key key) {
        Assert.notNull(key, "Key argument cannot be null.");
        for (JwkConverter<?> converter : converters.values()) {
            if (converter.supports(key)) {
                @SuppressWarnings("unchecked") // converter indicates it supports the key type, so we can pass through
                JwkConverter<Key> conv = (JwkConverter<Key>)converter;
                return conv.applyTo(key);
            }
        }

        String msg = "Unable to determine JWK converter for key of type " + key.getClass();
        throw new UnsupportedKeyException(msg);
    }

    @Override
    public Key applyFrom(Map<String, ?> jwk) {
        String type = getRequiredString(jwk, DefaultJwk.TYPE);
        JwkConverter<?> converter = getConverter(type);
        return converter.applyFrom(jwk);
    }
}
