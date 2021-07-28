package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.io.CodecConverter;
import io.jsonwebtoken.impl.lang.BiFunction;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.NullSafeConverter;
import io.jsonwebtoken.impl.lang.UriStringConverter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Identifiable;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.MalformedKeyException;

import java.lang.reflect.Field;
import java.net.URI;
import java.security.Key;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultJwkBuilder<K extends Key, J extends DefaultJwk<K>, T extends JwkBuilder<K, J, T>> implements JwkBuilder<K, J, T> {

    private static final Converter<byte[], Object> THUMBPRINT_CONVERTER =
        Converters.forEncoded(byte[].class, CodecConverter.BASE64URL);

    private static final Converter<X509Certificate, Object> X509_CONVERTER =
        Converters.forEncoded(X509Certificate.class, new JwkX509StringConverter());

    private static final Converter<URI, Object> URI_CONVERTER =
        Converters.forEncoded(URI.class, new UriStringConverter());

    private static final Map<String, SetterFunction<?, DefaultJwkBuilder<?, ?, ?>>> SETTERS;

    static {
        @SuppressWarnings("unchecked")
        List<SetterFunction<?, DefaultJwkBuilder<?, ?, ?>>> fns = Collections.of(

            SetterFunction.of(DefaultJwk.TYPE, "type", "Key Type"),

            SetterFunction.of(DefaultJwk.USE, "use", "Public Key Use"),

            SetterFunction.of(DefaultJwk.OPERATIONS, "operations", "Key Operations", Converters.forSetOf(String.class)),

            SetterFunction.of(DefaultJwk.ALGORITHM, "algorithm", "Algorithm"),

            SetterFunction.of(DefaultJwk.ID, "id", "Key ID"),

            SetterFunction.of(DefaultJwk.X509_URL, "x509Url", "X.509 URL", URI_CONVERTER),

            SetterFunction.of(DefaultJwk.X509_CERT_CHAIN, "x509CertificateChain", "X.509 Certificate Chain", Converters.forList(X509_CONVERTER)),

            SetterFunction.of(DefaultJwk.X509_SHA1_THUMBPRINT, "x509Sha1Thumbprint", "X.509 Certificate SHA-1 Thumbprint", THUMBPRINT_CONVERTER),

            SetterFunction.of(DefaultJwk.X509_SHA256_THUMBPRINT, "x509Sha256Thumbprint", "X.509 Certificate SHA-256 Thumbprint", THUMBPRINT_CONVERTER)
        );
        Map<String, SetterFunction<?, DefaultJwkBuilder<?, ?, ?>>> s = new LinkedHashMap<>();
        for (SetterFunction<?, DefaultJwkBuilder<?, ?, ?>> fn : fns) {
            s.put(fn.getId(), fn);
        }
        SETTERS = s;
    }

    protected final Map<String, Object> values = new LinkedHashMap<>();
    protected Provider provider;
    protected String algorithm;
    protected String id;
    protected Set<String> operations;
    protected String type;
    protected K key;

    protected final Converter<Key, Map<String, ?>> jwkConverter = new DispatchingJwkConverter();

    public DefaultJwkBuilder() {
    }

    @SuppressWarnings("unused") //used via reflection by the Jwks utility class
    public DefaultJwkBuilder(K key) {
        this();
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    @Override
    public T setProvider(Provider provider) {
        this.provider = Assert.notNull(provider, "Provider cannot be null.");
        return tthis();
    }

    protected T nullSafePut(String name, Object value) {
        if (DefaultJwk.isReduceableToNull(value)) {
            this.values.remove(name);
        } else {
            this.values.put(name, value);
        }
        return tthis();
    }

    private void doPut(String name, Object value) {
        assert name != null;
        assert value != null; //asserted by caller, guaranteed to be non-null and if a collection, non-empty
        SetterFunction<?, DefaultJwkBuilder<?, ?, ?>> fn = SETTERS.get(name);
        if (fn != null) {
            fn.apply(this, value);
        } else {
            nullSafePut(name, value);
        }
    }

    @Override
    public T put(String name, Object value) {
        name = Assert.notNull(Strings.clean(name), "JWK member name cannot be null or empty.");
        if (value instanceof String) {
            value = Strings.clean((String) value);
        } else if (Objects.isArray(value) && !value.getClass().getComponentType().isPrimitive()) {
            value = Collections.arrayToList(value);
        }
        if (DefaultJwk.isReduceableToNull(value)) {
            this.values.remove(name);
        } else {
            doPut(name, value);
        }
        return tthis();
    }

    @SuppressWarnings("unchecked")
    protected final T tthis() {
        return (T) this;
    }

    @Override
    public T putAll(Map<String, ?> values) {
        Assert.notEmpty(values, "Values map cannot be null or empty.");
        for (Map.Entry<String, ?> entry : values.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
        return tthis();
    }

    @Override
    public T setAlgorithm(String alg) {
        return put(DefaultJwk.ALGORITHM, alg);
    }

    @Override
    public T setId(String id) {
        return put(DefaultJwk.ID, id);
    }

    @Override
    public T setOperations(Set<String> ops) {
        return put(DefaultJwk.OPERATIONS, ops);
    }

    @Override
    public J build() {
        if (this.key == null) { //create one based on values
            this.key = (K) jwkConverter.applyFrom(this.values);
        } else {
            Map<String, ?> jwkValues = jwkConverter.applyTo(this.key);
            putAll(jwkValues);
        }
        return createJwk();
    }

    @SuppressWarnings("unchecked")
    protected J createJwk() {
        DefaultJwk<K> jwk = new DefaultJwk<>(this.type, this.operations, this.algorithm, this.id, this.key, this.values);
        return (J) jwk;
    }

    private static class SetterFunction<T, B extends DefaultJwkBuilder<?, ?, ?>> implements BiFunction<B, Object, B>, Identifiable {

        private final String id;
        private final String fieldName;
        private final String title;
        private final Converter<T, Object> converter;

        public static <B extends DefaultJwkBuilder<?, ?, ?>> SetterFunction<String, B> of(String id, String fieldName, String title) {
            return of(id, fieldName, title, Converters.none(String.class));
        }

        public static <T, B extends DefaultJwkBuilder<?, ?, ?>> SetterFunction<T, B> of(String id, String fieldName, String title, Converter<T, Object> converter) {
            return new SetterFunction<>(id, fieldName, title, new NullSafeConverter<>(converter));
        }

        public SetterFunction(String id, String fieldName, String title, Converter<T, Object> converter) {
            this.id = id;
            this.fieldName = fieldName;
            this.title = title;
            this.converter = converter;
        }

        @Override
        public String getId() {
            return this.id;
        }

        @Override
        public B apply(B builder, Object value) {

            if (value instanceof String) {
                value = Strings.clean((String) value);
            }

            if (DefaultJwk.isReduceableToNull(value)) {
                setField(builder, fieldName, null);
                builder.values.remove(id);
                return builder;
            }

            T fieldValue;
            Object encodedValue;
            try {
                fieldValue = converter.applyFrom(value);
                encodedValue = converter.applyTo(fieldValue);
            } catch (Exception e) {
                String msg = "Invalid JWK " + title + "('" + id + "') value [" + value + "]: " + e.getMessage();
                throw new MalformedKeyException(msg, e);
            }
            builder.nullSafePut(id, encodedValue);
            setField(builder, fieldName, fieldValue);

            return builder;
        }

        private void setField(Object target, String name, Object value) {
            try {
                Field field = target.getClass().getDeclaredField(name);
                field.setAccessible(true);
                field.set(this, value);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                String msg = "Unable to access self property via reflection which should always be allowed. This is " +
                    "likely an internal JJWT programming error. Please report it to the JJWT team immediately. Message: " +
                    e.getMessage();
                throw new IllegalStateException(msg, e);
            }
        }
    }
}
