package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.DynamicJwkBuilder;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperationPolicy;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.MalformedKeySetException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultJwkSetParser extends AbstractJwkParser<JwkSet> {

    private final Converter<Jwk<?>, Object> CONVERTER;

    @SuppressWarnings("unchecked")
    public DefaultJwkSetParser(final Provider provider,
                               Deserializer<Map<String, ?>> deserializer,
                               final KeyOperationPolicy policy) {

        super(provider, deserializer, policy);

        Supplier<DynamicJwkBuilder<?, ?>> supplier = new Supplier<DynamicJwkBuilder<?, ?>>() {
            @Override
            public DynamicJwkBuilder<?, ?> get() {
                return Jwks.builder().provider(provider).operationPolicy(policy);
            }
        };
        this.CONVERTER = new JwkConverter<>((Class<Jwk<?>>) (Class<?>) Jwk.class, supplier);
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

        // ensure DefaultJwkSet instance reflects our specific converter that reflects potential
        // user-configured Provider and KeyOperationPolicy:
        Field<Set<Jwk<?>>> field = DefaultJwkSet.field(this.CONVERTER);

        if (Collections.isEmpty(m) | !m.containsKey(field.getId())) {
            throw new MalformedKeySetException("Missing required JWK Set 'keys' member.");
        }

        Object val = m.get(field.getId());
        if (val == null) {
            String msg = "JWK Set 'keys' value cannot be null.";
            throw new MalformedKeySetException(msg);
        }
        if (!(val instanceof Collection)) {
            String msg = "JWK Set 'keys' value must be a Collection (JSON Array). Type found: " +
                    val.getClass().getName();
            throw new MalformedKeySetException(msg);
        }
        int size = Collections.size((Collection<?>) val);
        if (size == 0) {
            String msg = "JWK Set 'keys' value is empty.";
            throw new MalformedKeySetException(msg);
        }

        List<?> vals = new ArrayList<>((Collection<?>) val);
        Set<Jwk<?>> jwks = new LinkedHashSet<>(size);
        for (int i = 0; i < size; i++) { // we iterate with a counter so we can indicate which element fails (if any)
            val = vals.get(i);
            if (val == null) {
                String msg = "JWK Set keys[" + i + "] element is null.";
                throw new MalformedKeySetException(msg);
            }
            if (!(val instanceof Map)) {
                String msg = "JWK Set keys[" + i + "] element is not a JSON Object. Type found: " +
                        val.getClass().getName();
                throw new MalformedKeySetException(msg);
            }
            Map<?, ?> mval = (Map<?, ?>) val;
            if (Collections.size(mval) == 0) {
                String msg = "JWK Set keys[" + i + "] element is an empty JSON Object.";
                throw new MalformedKeySetException(msg);
            }
            try {
                Jwk<?> jwk = convertJwk(mval);
                jwks.add(jwk);
            } catch (Throwable t) {
                String msg = "JWK Set keys[" + i + "]: " + t.getMessage();
                if (t instanceof IllegalArgumentException || t instanceof MalformedKeyException) {
                    throw new MalformedKeySetException(msg, t);
                }
                // otherwise propagate:
                throw new UnsupportedKeyException(msg, t);
            }
        }

        // Copy values and replace the `keys` value with (immutable) validated entries:
        Map<String, Object> src = new LinkedHashMap<>(m);
        src.remove(field.getId());
        src.put(field.getId(), Collections.immutable(jwks));
        return new DefaultJwkSet(field, src);
    }

    protected Jwk<?> convertJwk(Map<?, ?> map) {
        return this.CONVERTER.applyFrom(map);
    }
}
