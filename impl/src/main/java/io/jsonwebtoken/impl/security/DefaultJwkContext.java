package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.JwtMap;
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
import io.jsonwebtoken.security.MalformedKeyException;

import java.net.URI;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultJwkContext<K extends Key> implements JwkContext<K> {

    private static final Converter<byte[], Object> THUMBPRINT_CONVERTER =
        Converters.forEncoded(byte[].class, CodecConverter.BASE64URL);

    private static final Converter<X509Certificate, Object> X509_CONVERTER =
        Converters.forEncoded(X509Certificate.class, new JwkX509StringConverter());

    private static final Converter<URI, Object> URI_CONVERTER =
        Converters.forEncoded(URI.class, new UriStringConverter());

    private static final Map<String, Canonicalizer<?>> SETTERS;

    static {
        @SuppressWarnings("RedundantTypeArguments")
        List<Canonicalizer<?>> fns = Collections.<Canonicalizer<?>>of(
            Canonicalizer.forKey(AbstractJwk.ALGORITHM, "Algorithm"),
            Canonicalizer.forKey(AbstractJwk.ID, "Key ID"),
            Canonicalizer.forKey(AbstractJwk.OPERATIONS, "Key Operations", Converters.forSetOf(String.class)),
            Canonicalizer.forKey(AbstractAsymmetricJwk.PUBLIC_KEY_USE, "Public Key Use"),
            Canonicalizer.forKey(AbstractJwk.TYPE, "Key Type"),
            Canonicalizer.forKey(AbstractAsymmetricJwk.X509_CERT_CHAIN, "X.509 Certificate Chain", Converters.forList(X509_CONVERTER)),
            Canonicalizer.forKey(AbstractAsymmetricJwk.X509_SHA1_THUMBPRINT, "X.509 Certificate SHA-1 Thumbprint", THUMBPRINT_CONVERTER),
            Canonicalizer.forKey(AbstractAsymmetricJwk.X509_SHA256_THUMBPRINT, "X.509 Certificate SHA-256 Thumbprint", THUMBPRINT_CONVERTER),
            Canonicalizer.forKey(AbstractAsymmetricJwk.X509_URL, "X.509 URL", URI_CONVERTER)
        );
        Map<String, Canonicalizer<?>> s = new LinkedHashMap<>();
        for (Canonicalizer<?> fn : fns) {
            s.put(fn.getId(), fn);
        }
        SETTERS = s;
    }

    private final Map<String, Object> values;
    private final Map<String, Object> canonicalValues;
    private final Map<String, Object> redactedValues;
    private final Set<String> privateMemberNames;
    private K key;
    private PublicKey publicKey;
    private Provider provider;

    public DefaultJwkContext() {
        this.values = new LinkedHashMap<>();
        this.canonicalValues = new LinkedHashMap<>();
        this.redactedValues = new LinkedHashMap<>();
        this.privateMemberNames = Collections.emptySet();
    }

//    public DefaultJwkContext(JwkContext<?> other) {
//        //noinspection unchecked
//        this(other,
//            (Assert.isInstanceOf(DefaultJwkContext.class, other, "JwkContext must be a DefaultJwkContext instance.")).privateMemberNames);
//    }

    public DefaultJwkContext(JwkContext<?> other, Set<String> privateMemberNames) {
        Assert.notNull(other, "JwkContext cannot be null.");
        Assert.isInstanceOf(DefaultJwkContext.class, other, "JwkContext must be a DefaultJwkContext instance.");
        DefaultJwkContext<?> src = (DefaultJwkContext<?>) other;
        this.privateMemberNames = Assert.notEmpty(privateMemberNames, "privateMemberNames cannot be null or empty.");
        this.provider = other.getProvider();
        this.values = new LinkedHashMap<>(src.values);
        this.canonicalValues = new LinkedHashMap<>(src.values);
        this.redactedValues = new LinkedHashMap<>(this.values);

        //if the key is a PublicKey, we don't even want to redact - we want to fully remove the items that are
        //private names (public JWKs should never contain any private key fields, even if redacted):
        final Key key = other.getKey();
        final boolean remove = (key == null || key instanceof PublicKey);
        for (String name : this.privateMemberNames) {
            if (remove) {
                remove(name);
            } else if (this.redactedValues.containsKey(name)) { //otherwise ensure redacted for toString calls:
                this.redactedValues.put(name, AbstractJwk.REDACTED_VALUE);
            }
        }
    }

    public DefaultJwkContext(JwkContext<?> other, K key, Set<String> privateMemberNames) {
        this(other, privateMemberNames);
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    protected Object nullSafePut(String name, Object value) {
        if (JwtMap.isReduceableToNull(value)) {
            return remove(name);
        } else {
            Object redactedValue = this.privateMemberNames.contains(name) ? AbstractJwk.REDACTED_VALUE : value;
            this.redactedValues.put(name, redactedValue);
            this.canonicalValues.put(name, value);
            return this.values.put(name, value);
        }
    }

    @Override
    public Object put(String name, Object value) {
        name = Assert.notNull(Strings.clean(name), "JWK member name cannot be null or empty.");
        if (value instanceof String) {
            value = Strings.clean((String) value);
        } else if (Objects.isArray(value) && !value.getClass().getComponentType().isPrimitive()) {
            value = Collections.arrayToList(value);
        }
        return doPut(name, value);
    }

    private Object doPut(String name, Object value) {
        assert name != null; //asserted by caller.
        Canonicalizer<?> fn = SETTERS.get(name);
        if (fn != null) { //Setting a JWA-standard property - let's ensure we can represent it canonically:
            return fn.apply(this, value);
        } else { //non-standard/custom property:
            return nullSafePut(name, value);
        }
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        Assert.notEmpty(m, "JWK values cannot be null or empty.");
        for (Map.Entry<? extends String, ?> entry : m.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    private Object remove(String key) {
        this.redactedValues.remove(key);
        this.canonicalValues.remove(key);
        return this.values.remove(key);
    }

    @Override
    public int size() {
        return this.values.size();
    }

    @Override
    public boolean isEmpty() {
        return this.values.isEmpty();
    }

    @Override
    public boolean containsKey(String key) {
        return this.values.containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return this.values.containsValue(value);
    }

    @Override
    public Object get(String key) {
        return this.values.get(key);
    }

    @Override
    public Set<String> keySet() {
        return this.values.keySet();
    }

    @Override
    public Collection<Object> values() {
        return this.values.values();
    }

    @Override
    public Set<Map.Entry<String, Object>> entrySet() {
        return this.values.entrySet();
    }

    @Override
    public Map<String, Object> getValues() {
        return this.values;
    }

    @Override
    public String getAlgorithm() {
        return (String) this.canonicalValues.get(AbstractJwk.ALGORITHM);
    }

    @Override
    public void setAlgorithm(String algorithm) {
        put(AbstractJwk.ALGORITHM, algorithm);
    }

    @Override
    public String getId() {
        return (String) this.canonicalValues.get(AbstractJwk.ID);
    }

    @Override
    public void setId(String id) {
        put(AbstractJwk.ID, id);
    }

    @Override
    public Set<String> getOperations() {
        //noinspection unchecked
        return (Set<String>) this.canonicalValues.get(AbstractJwk.OPERATIONS);
    }

    @Override
    public void setOperations(Set<String> ops) {
        put(AbstractJwk.OPERATIONS, ops);
    }

    @Override
    public String getType() {
        return (String) this.canonicalValues.get(AbstractJwk.TYPE);
    }

    @Override
    public void setType(String type) {
        put(AbstractJwk.TYPE, type);
    }

    @Override
    public String getPublicKeyUse() {
        return (String) this.canonicalValues.get(AbstractAsymmetricJwk.PUBLIC_KEY_USE);
    }

    @Override
    public void setPublicKeyUse(String use) {
        put(AbstractAsymmetricJwk.PUBLIC_KEY_USE, use);
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        //noinspection unchecked
        return (List<X509Certificate>) this.canonicalValues.get(AbstractAsymmetricJwk.X509_CERT_CHAIN);
    }

    @Override
    public void setX509CertificateChain(List<X509Certificate> x5c) {
        put(AbstractAsymmetricJwk.X509_CERT_CHAIN, x5c);
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return (byte[]) this.canonicalValues.get(AbstractAsymmetricJwk.X509_SHA1_THUMBPRINT);
    }

    @Override
    public void setX509CertificateSha1Thumbprint(byte[] x5t) {
        put(AbstractAsymmetricJwk.X509_SHA1_THUMBPRINT, x5t);
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return (byte[]) this.canonicalValues.get(AbstractAsymmetricJwk.X509_SHA256_THUMBPRINT);
    }

    @Override
    public void setX509CertificateSha256Thumbprint(byte[] x5ts256) {
        put(AbstractAsymmetricJwk.X509_SHA256_THUMBPRINT, x5ts256);
    }

    @Override
    public URI getX509Url() {
        return (URI) this.canonicalValues.get(AbstractAsymmetricJwk.X509_URL);
    }

    @Override
    public void setX509Url(URI url) {
        put(AbstractAsymmetricJwk.X509_URL, url);
    }

    @Override
    public K getKey() {
        return this.key;
    }

    @Override
    public JwkContext<K> setKey(K key) {
        this.key = key;
        return this;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public void setProvider(Provider provider) {
        this.provider = provider;
    }

    @Override
    public Set<String> getPrivateMemberNames() {
        return this.privateMemberNames;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = hash * 31 + Objects.nullSafeHashCode(this.key);
        hash = hash * 31 + Objects.nullSafeHashCode(this.values);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof DefaultJwkContext) {
            DefaultJwkContext<?> c = (DefaultJwkContext<?>) obj;
            return Objects.nullSafeEquals(this.key, c.key) &&
                Objects.nullSafeEquals(this.values, c.values);
        }
        return false;
    }

    @Override
    public String toString() {
        return this.redactedValues.toString();
    }

    private static class Canonicalizer<T> implements BiFunction<DefaultJwkContext<?>, Object, T>, Identifiable {

        private final String id;
        private final String title;
        private final Converter<T, Object> converter;

        public static Canonicalizer<String> forKey(String id, String title) {
            return forKey(id, title, Converters.none(String.class));
        }

        public static <T> Canonicalizer<T> forKey(String id, String title, Converter<T, Object> converter) {
            return new Canonicalizer<>(id, title, new NullSafeConverter<>(converter));
        }

        public Canonicalizer(String id, String title, Converter<T, Object> converter) {
            this.id = id;
            this.title = title;
            this.converter = converter;
        }

        @Override
        public String getId() {
            return this.id;
        }

        @Override
        public T apply(DefaultJwkContext<?> ctx, Object rawValue) {

            if (JwtMap.isReduceableToNull(rawValue)) {
                //noinspection unchecked
                return (T) ctx.remove(id);
            }

            T canonicalValue;
            Object encodedValue;
            try {
                canonicalValue = converter.applyFrom(rawValue);
                encodedValue = converter.applyTo(canonicalValue);
            } catch (Exception e) {
                String msg = "Invalid JWK " + title + "('" + id + "') value [" + rawValue + "]: " + e.getMessage();
                throw new MalformedKeyException(msg, e);
            }
            ctx.nullSafePut(id, encodedValue);
            ctx.canonicalValues.put(id, canonicalValue);
            //noinspection unchecked
            return (T) encodedValue;
        }
    }
}
