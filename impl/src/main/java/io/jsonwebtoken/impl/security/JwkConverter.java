package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;
import io.jsonwebtoken.security.SecretJwk;

import java.util.Map;

public final class JwkConverter<T extends Jwk<?>> implements Converter<T, Object> {

    @SuppressWarnings("unchecked")
    public static final JwkConverter<PublicJwk<?>> PUBLIC_JWK = new JwkConverter<>((Class<PublicJwk<?>>) (Class<?>) PublicJwk.class);

    public static final JwkConverter<EcPublicJwk> EC_PUBLIC_JWK = new JwkConverter<>(EcPublicJwk.class);

    private final Class<T> desiredType;

    public JwkConverter(Class<T> desiredType) {
        this.desiredType = Assert.notNull(desiredType, "desiredType cannot be null.");
    }

    @Override
    public Object applyTo(T jwk) {
        return desiredType.cast(jwk);
    }

    private static String articleFor(String s) {
        switch (s.charAt(0)) {
            case 'E': // for Elliptic Curve
            case 'R': // for RSA
                return "an";
            default:
                return "a";
        }
    }

    private static String typeString(Jwk<?> jwk) {
        Assert.isInstanceOf(Nameable.class, jwk, "All JWK implementations must implement Nameable.");
        return ((Nameable)jwk).getName();
    }

    private static String typeString(Class<?> clazz) {
        StringBuilder sb = new StringBuilder();
        if (SecretJwk.class.isAssignableFrom(clazz)) {
            sb.append("Secret");
        } else if (RsaPublicJwk.class.isAssignableFrom(clazz) || RsaPrivateJwk.class.isAssignableFrom(clazz)) {
            sb.append("RSA");
        } else if (EcPublicJwk.class.isAssignableFrom(clazz) || EcPrivateJwk.class.isAssignableFrom(clazz)) {
            sb.append("EC");
        }
        return typeString(sb, clazz);
    }

    private static String typeString(StringBuilder sb, Class<?> clazz) {
        if (PublicJwk.class.isAssignableFrom(clazz)) {
            if (sb.length() != 0) {
                sb.append(' ');
            }
            sb.append("Public");
        } else if (PrivateJwk.class.isAssignableFrom(clazz)) {
            if (sb.length() != 0) {
                sb.append(' ');
            }
            sb.append("Private");
        }
        if (sb.length() != 0) {
            sb.append(' ');
        }
        sb.append("JWK");
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
        Assert.notNull(o, "JWK argument cannot be null.");
        if (desiredType.isInstance(o)) {
            return desiredType.cast(o);
        } else if (o instanceof Jwk<?>) {
            throw unexpectedIAE((Jwk<?>) o);
        }
        if (!(o instanceof Map)) {
            String msg = "Value must be a Jwk<?> or Map<String,?>. Type found: " + o.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
        Map<?, ?> map = (Map<?, ?>) o;
        JwkBuilder<?, ?, ?> builder = Jwks.builder();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            Assert.notNull(key, "JWK map key cannot be null.");
            if (!(key instanceof String)) {
                String msg = "JWK map keys must be Strings. Encountered key '" + key + "' of type " +
                        key.getClass().getName() + ".";
                throw new IllegalArgumentException(msg);
            }
            String skey = (String) key;
            builder.put(skey, entry.getValue());
        }

        Jwk<?> jwk = builder.build();
        if (desiredType.isInstance(jwk)) {
            return desiredType.cast(jwk);
        }
        throw unexpectedIAE(jwk);
    }
}
