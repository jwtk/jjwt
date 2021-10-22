package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.JwtMap;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;

import java.net.URI;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultJwkContext<K extends Key> extends JwtMap implements JwkContext<K> {

    private static final Set<Field<?>> DEFAULT_FIELDS;
    static { // assume all known fields:
        Set<Field<?>> set = new LinkedHashSet<>();
        set.addAll(DefaultSecretJwk.FIELDS); // Private/Secret JWKs has both public and private fields
        set.addAll(DefaultEcPrivateJwk.FIELDS); // Private JWKs have both public and private fields
        set.addAll(DefaultRsaPrivateJwk.FIELDS); // Private JWKs have both public and private fields
        DEFAULT_FIELDS = Collections.immutable(set);
    }

    private K key;
    private PublicKey publicKey;
    private Provider provider;

    public DefaultJwkContext() {
        // For the default constructor case, we don't know how it will be used or what values will be populated,
        // so we can't know ahead of time what the sensitive data is.  As such, for security reasons, we assume all
        // the known fields for all supported keys/algorithms in case it is used for any of them:
        this(DEFAULT_FIELDS);
    }

    public DefaultJwkContext(Set<Field<?>> fields) {
        super(fields);
    }

    public DefaultJwkContext(Set<Field<?>> fields, JwkContext<?> other) {
        this(fields, other, true);
    }

    public DefaultJwkContext(Set<Field<?>> fields, JwkContext<?> other, K key) {
        //if the key is null or a PublicKey, we don't want to redact - we want to fully remove the items that are
        //private names (public JWKs should never contain any private key fields, even if redacted):
        this(fields, other, (key == null || key instanceof PublicKey));
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    private DefaultJwkContext(Set<Field<?>> fields, JwkContext<?> other, boolean removePrivate) {
        super(Assert.notEmpty(fields, "Fields cannot be null or empty."));
        Assert.notNull(other, "JwkContext cannot be null.");
        Assert.isInstanceOf(DefaultJwkContext.class, other, "JwkContext must be a DefaultJwkContext instance.");
        DefaultJwkContext<?> src = (DefaultJwkContext<?>) other;
        this.provider = other.getProvider();
        this.values.putAll(src.values);
        this.idiomaticValues.putAll(src.idiomaticValues);
        this.redactedValues.putAll(src.redactedValues);
        if (removePrivate) {
            for(Field<?> field : src.FIELDS.values()) {
                if (field.isSecret()) {
                    remove(field.getId());
                }
            }
        }
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        Assert.notEmpty(m, "JWK values cannot be null or empty.");
        super.putAll(m);
    }

    @Override
    public String getAlgorithm() {
        return (String) this.values.get(AbstractJwk.ALG.getId());
    }

    @Override
    public JwkContext<K> setAlgorithm(String algorithm) {
        put(AbstractJwk.ALG.getId(), algorithm);
        return this;
    }

    @Override
    public String getId() {
        return (String) this.values.get(AbstractJwk.KID.getId());
    }

    @Override
    public JwkContext<K> setId(String id) {
        put(AbstractJwk.KID.getId(), id);
        return this;
    }

    @Override
    public Set<String> getOperations() {
        //noinspection unchecked
        return (Set<String>) this.idiomaticValues.get(AbstractJwk.KEY_OPS.getId());
    }

    @Override
    public JwkContext<K> setOperations(Set<String> ops) {
        put(AbstractJwk.KEY_OPS.getId(), ops);
        return this;
    }

    @Override
    public String getType() {
        return (String) this.values.get(AbstractJwk.KTY.getId());
    }

    @Override
    public JwkContext<K> setType(String type) {
        put(AbstractJwk.KTY.getId(), type);
        return this;
    }

    @Override
    public String getPublicKeyUse() {
        return (String) this.values.get(AbstractAsymmetricJwk.USE.getId());
    }

    @Override
    public JwkContext<K> setPublicKeyUse(String use) {
        put(AbstractAsymmetricJwk.USE.getId(), use);
        return this;
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        //noinspection unchecked
        return (List<X509Certificate>) this.idiomaticValues.get(AbstractAsymmetricJwk.X5C.getId());
    }

    @Override
    public JwkContext<K> setX509CertificateChain(List<X509Certificate> x5c) {
        put(AbstractAsymmetricJwk.X5C.getId(), x5c);
        return this;
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return (byte[]) this.idiomaticValues.get(AbstractAsymmetricJwk.X5T.getId());
    }

    @Override
    public JwkContext<K> setX509CertificateSha1Thumbprint(byte[] x5t) {
        put(AbstractAsymmetricJwk.X5T.getId(), x5t);
        return this;
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return (byte[]) this.idiomaticValues.get(AbstractAsymmetricJwk.X5T_S256.getId());
    }

    @Override
    public JwkContext<K> setX509CertificateSha256Thumbprint(byte[] x5ts256) {
        put(AbstractAsymmetricJwk.X5T_S256.getId(), x5ts256);
        return this;
    }

    @Override
    public URI getX509Url() {
        return (URI) this.idiomaticValues.get(AbstractAsymmetricJwk.X5U.getId());
    }

    @Override
    public JwkContext<K> setX509Url(URI url) {
        put(AbstractAsymmetricJwk.X5U.getId(), url);
        return this;
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
    public JwkContext<K> setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public JwkContext<K> setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }
}
