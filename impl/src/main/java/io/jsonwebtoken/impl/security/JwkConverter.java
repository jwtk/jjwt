/*
 * Copyright (C) 2021 jsonwebtoken.io
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
import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.DynamicJwkBuilder;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.OctetPrivateJwk;
import io.jsonwebtoken.security.OctetPublicJwk;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;
import io.jsonwebtoken.security.SecretJwk;

import java.util.Map;

import static io.jsonwebtoken.lang.Strings.nespace;

public final class JwkConverter<T extends Jwk<?>> implements Converter<T, Object> {

    @SuppressWarnings("unchecked")
    public static final Class<Jwk<?>> JWK_CLASS = (Class<Jwk<?>>) (Class<?>) Jwk.class;

    @SuppressWarnings("unchecked")
    public static final Class<PublicJwk<?>> PUBLIC_JWK_CLASS = (Class<PublicJwk<?>>) (Class<?>) PublicJwk.class;

    public static final JwkConverter<Jwk<?>> ANY = new JwkConverter<>(JWK_CLASS);

    public static final JwkConverter<PublicJwk<?>> PUBLIC_JWK = new JwkConverter<>(PUBLIC_JWK_CLASS);

    private final Class<T> desiredType;

    private final Supplier<DynamicJwkBuilder<?, ?>> supplier;

    public JwkConverter(Class<T> desiredType) {
        this(desiredType, JwkBuilderSupplier.DEFAULT);
    }

    @SuppressWarnings("unchecked")
    public JwkConverter(Supplier<DynamicJwkBuilder<?, ?>> supplier) {
        this((Class<T>) JWK_CLASS, supplier);
    }

    public JwkConverter(Class<T> desiredType, Supplier<DynamicJwkBuilder<?, ?>> supplier) {
        this.desiredType = Assert.notNull(desiredType, "desiredType cannot be null.");
        this.supplier = Assert.notNull(supplier, "supplier cannot be null.");
    }

    @Override
    public Object applyTo(T jwk) {
        return desiredType.cast(jwk);
    }

    private static String articleFor(String s) {
        switch (s.charAt(0)) {
            case 'E': // for Elliptic/Edwards Curve
            case 'R': // for RSA
                return "an";
            default:
                return "a";
        }
    }

    private static String typeString(Jwk<?> jwk) {
        Assert.isInstanceOf(Nameable.class, jwk, "All JWK implementations must implement Nameable.");
        return ((Nameable) jwk).getName();
    }

    private static String typeString(Class<?> clazz) {
        StringBuilder sb = new StringBuilder();
        if (SecretJwk.class.isAssignableFrom(clazz)) {
            sb.append("Secret");
        } else if (RsaPublicJwk.class.isAssignableFrom(clazz) || RsaPrivateJwk.class.isAssignableFrom(clazz)) {
            sb.append("RSA");
        } else if (EcPublicJwk.class.isAssignableFrom(clazz) || EcPrivateJwk.class.isAssignableFrom(clazz)) {
            sb.append("EC");
        } else if (OctetPublicJwk.class.isAssignableFrom(clazz) || OctetPrivateJwk.class.isAssignableFrom(clazz)) {
            sb.append("Edwards Curve");
        }
        return typeString(sb, clazz);
    }

    private static String typeString(StringBuilder sb, Class<?> clazz) {
        if (PublicJwk.class.isAssignableFrom(clazz)) {
            nespace(sb).append("Public");
        } else if (PrivateJwk.class.isAssignableFrom(clazz)) {
            nespace(sb).append("Private");
        }
        nespace(sb).append("JWK");
        return sb.toString();
    }

    private IllegalArgumentException unexpectedIAE(Jwk<?> jwk) {
        String desired = typeString(this.desiredType);
        String jwkType = typeString(jwk);
        String msg = "Value must be " + articleFor(desired) + " " + desired + ", not " +
                articleFor(jwkType) + " " + jwkType + ".";
        return new IllegalArgumentException(msg);
    }

    @Override
    public T applyFrom(Object o) {
        Assert.notNull(o, "JWK cannot be null.");
        if (desiredType.isInstance(o)) {
            return desiredType.cast(o);
        } else if (o instanceof Jwk<?>) {
            throw unexpectedIAE((Jwk<?>) o);
        }
        if (!(o instanceof Map)) {
            String msg = "JWK must be a Map<String,?> (JSON Object). Type found: " + o.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
        final Map<?, ?> map = Collections.immutable((Map<?, ?>) o);

        Parameter<String> param = AbstractJwk.KTY;
        // mandatory for all JWKs: https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
        // no need for builder param type conversion overhead if this isn't present:
        if (Collections.isEmpty(map) || !map.containsKey(param.getId())) {
            String msg = "JWK is missing required " + param + " parameter.";
            throw new MalformedKeyException(msg);
        }
        Object val = map.get(param.getId());
        if (val == null) {
            String msg = "JWK " + param + " value cannot be null.";
            throw new MalformedKeyException(msg);
        }
        if (!(val instanceof String)) {
            String msg = "JWK " + param + " value must be a String. Type found: " + val.getClass().getName();
            throw new MalformedKeyException(msg);
        }
        String kty = (String) val;
        if (!Strings.hasText(kty)) {
            String msg = "JWK " + param + " value cannot be empty.";
            throw new MalformedKeyException(msg);
        }

        DynamicJwkBuilder<?, ?> builder = this.supplier.get();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            Assert.notNull(key, "JWK map key cannot be null.");
            if (!(key instanceof String)) {
                String msg = "JWK map keys must be Strings. Encountered key '" + key + "' of type " +
                        key.getClass().getName() + ".";
                throw new IllegalArgumentException(msg);
            }
            String skey = (String) key;
            builder.add(skey, entry.getValue());
        }
        Jwk<?> jwk = builder.build();

        if (desiredType.isInstance(jwk)) {
            return desiredType.cast(jwk);
        }
        throw unexpectedIAE(jwk);
    }
}
