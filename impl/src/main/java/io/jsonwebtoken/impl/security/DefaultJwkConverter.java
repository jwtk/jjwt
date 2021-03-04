package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultJwkConverter extends AbstractJwkConverter {

    private final Map<String, TypedJwkConverter> converters = new HashMap<>();

    public DefaultJwkConverter() {
        this(Collections.<TypedJwkConverter>of(
            new SymmetricJwkConverter(),
            new EcJwkConverter(),
            new RsaJwkConverter()));
    }

    public DefaultJwkConverter(List<TypedJwkConverter> converters) {
        Assert.notEmpty(converters, "Converters cannot be null or empty.");
        for(TypedJwkConverter converter : converters) {
            this.converters.put(converter.getKeyType(), converter);
        }
    }

    private JwkConverter getConverter(String kty) {
        JwkConverter converter = converters.get(kty);
        if (converter == null) {
            String msg = "Unrecognized JWK kty (key type) value: " + kty;
            throw new UnsupportedKeyException(msg);
        }
        return converter;
    }

    @Override
    public Key toKey(Map<String, ?> jwk) {
        String type = getRequiredString(jwk, "kty");
        JwkConverter converter = getConverter(type);
        return converter.toKey(jwk);
    }

    @Override
    public Map<String, String> toJwk(Key key) {
        Assert.notNull(key, "Key argument cannot be null.");
        for(TypedJwkConverter converter : converters.values()) {
            if (converter.supports(key)) {
                return converter.toJwk(key);
            }
        }

        String msg = "Unable to determine JWK converter for key of type " + key.getClass();
        throw new UnsupportedKeyException(msg);
    }
}
