package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.MalformedKeySetException;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class JwkSetConverter implements Converter<JwkSet, Object> {

    private final Converter<Jwk<?>, Object> JWK_CONVERTER;
    private final Field<Set<Jwk<?>>> FIELD;

    public JwkSetConverter(Converter<Jwk<?>, Object> jwkConverter) {
        this.JWK_CONVERTER = Assert.notNull(jwkConverter, "JWK converter cannot be null.");
        this.FIELD = DefaultJwkSet.field(jwkConverter);
    }

    @Override
    public Object applyTo(JwkSet jwkSet) {
        return jwkSet;
    }

    @Override
    public JwkSet applyFrom(Object o) {
        Assert.notNull(o, "Value cannot be null.");
        if (!(o instanceof Map)) {
            String msg = "Value must be a Map<String,?> (JSON Object). Type found: " + o.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
        final Map<?, ?> m = Collections.immutable((Map<?, ?>) o);

        // mandatory for all JWK Sets: https://datatracker.ietf.org/doc/html/rfc7517#section-5
        // no need for builder field type conversion overhead if this isn't present:
        if (Collections.isEmpty(m) || !m.containsKey(FIELD.getId())) {
            String msg = "Missing required " + FIELD + " parameter.";
            throw new MalformedKeySetException(msg);
        }
        Object val = m.get(FIELD.getId());
        if (val == null) {
            String msg = "JWK Set " + FIELD + " value cannot be null.";
            throw new MalformedKeySetException(msg);
        }
        if (!(val instanceof Collection)) {
            String msg = "JWK Set " + FIELD + " value must be a Collection (JSON Array). Type found: " +
                    val.getClass().getName();
            throw new MalformedKeySetException(msg);
        }
        int size = Collections.size((Collection<?>) val);
        if (size == 0) {
            String msg = "JWK Set " + FIELD + " collection cannot be empty.";
            throw new MalformedKeySetException(msg);
        }

        // Copy values so we don't mutate the original input
        Map<String, Object> src = new LinkedHashMap<>(Collections.size((Map<?, ?>) o));
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) o).entrySet()) {
            Object key = Assert.notNull(entry.getKey(), "JWK Set map key cannot be null.");
            if (!(key instanceof String)) {
                String msg = "JWK Set map keys must be Strings. Encountered key '" + key + "' of type " +
                        key.getClass().getName();
                throw new IllegalArgumentException(msg);
            }
            String skey = (String) key;
            src.put(skey, entry.getValue());
        }

        Set<Jwk<?>> jwks = new LinkedHashSet<>(size);
        int i = 0; // keep track of which element fails (if any)
        for (Object candidate : ((Collection<?>) val)) {
            try {
                Jwk<?> jwk = JWK_CONVERTER.applyFrom(candidate);
                jwks.add(jwk);
            } catch (IllegalArgumentException | MalformedKeyException e) {
                String msg = "JWK Set keys[" + i + "]: " + e.getMessage();
                throw new MalformedKeySetException(msg, e);
            }
            i++;
        }

        // Replace the `keys` value with (immutable) validated entries:
        src.remove(FIELD.getId());
        src.put(FIELD.getId(), Collections.immutable(jwks));
        return new DefaultJwkSet(FIELD, src);
    }
}
