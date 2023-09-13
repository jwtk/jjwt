/*
 * Copyright © 2023 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.DynamicJwkBuilder;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.MalformedKeySetException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class JwkSetConverter implements Converter<JwkSet, Object> {

    private final Converter<Jwk<?>, Object> JWK_CONVERTER;
    private final Parameter<Set<Jwk<?>>> PARAM;

    private final boolean ignoreUnsupported;

    public JwkSetConverter() {
        // ignore is true by default per https://www.rfc-editor.org/rfc/rfc7517.html#section-5:
        this(JwkBuilderSupplier.DEFAULT, true);
    }

    public JwkSetConverter(boolean ignoreUnsupported) {
        this(JwkBuilderSupplier.DEFAULT, ignoreUnsupported);
    }

    public JwkSetConverter(Supplier<DynamicJwkBuilder<?, ?>> supplier, boolean ignoreUnsupported) {
        this(new JwkConverter<>(supplier), ignoreUnsupported);
    }

    public JwkSetConverter(Converter<Jwk<?>, Object> jwkConverter, boolean ignoreUnsupported) {
        this.JWK_CONVERTER = Assert.notNull(jwkConverter, "JWK converter cannot be null.");
        this.PARAM = DefaultJwkSet.param(jwkConverter);
        this.ignoreUnsupported = ignoreUnsupported;
    }

    public boolean isIgnoreUnsupported() {
        return ignoreUnsupported;
    }

    @Override
    public Object applyTo(JwkSet jwkSet) {
        return jwkSet;
    }

    @Override
    public JwkSet applyFrom(Object o) {
        Assert.notNull(o, "Value cannot be null.");
        if (o instanceof JwkSet) {
            return (JwkSet) o;
        }
        if (!(o instanceof Map)) {
            String msg = "Value must be a Map<String,?> (JSON Object). Type found: " + o.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
        final Map<?, ?> m = Collections.immutable((Map<?, ?>) o);

        // mandatory for all JWK Sets: https://datatracker.ietf.org/doc/html/rfc7517#section-5
        // no need for builder parameter type conversion overhead if this isn't present:
        if (Collections.isEmpty(m) || !m.containsKey(PARAM.getId())) {
            String msg = "Missing required " + PARAM + " parameter.";
            throw new MalformedKeySetException(msg);
        }
        Object val = m.get(PARAM.getId());
        if (val == null) {
            String msg = "JWK Set " + PARAM + " value cannot be null.";
            throw new MalformedKeySetException(msg);
        }
        if (val instanceof Supplier<?>) {
            val = ((Supplier<?>) val).get();
        }
        if (!(val instanceof Collection)) {
            String msg = "JWK Set " + PARAM + " value must be a Collection (JSON Array). Type found: " +
                    val.getClass().getName();
            throw new MalformedKeySetException(msg);
        }
        int size = Collections.size((Collection<?>) val);
        if (size == 0) {
            String msg = "JWK Set " + PARAM + " collection cannot be empty.";
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
            } catch (UnsupportedKeyException e) {
                if (!ignoreUnsupported) {
                    String msg = "JWK Set keys[" + i + "]: " + e.getMessage();
                    throw new UnsupportedKeyException(msg, e);
                }
            } catch (IllegalArgumentException | KeyException e) {
                if (!ignoreUnsupported) {
                    String msg = "JWK Set keys[" + i + "]: " + e.getMessage();
                    throw new MalformedKeySetException(msg, e);
                }
            }
            i++;
        }

        // Replace the `keys` value with validated entries:
        src.remove(PARAM.getId());
        src.put(PARAM.getId(), jwks);
        return new DefaultJwkSet(PARAM, src);
    }
}
