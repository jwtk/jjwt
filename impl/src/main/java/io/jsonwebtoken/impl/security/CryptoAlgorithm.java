package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecretKeyBuilder;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
abstract class CryptoAlgorithm implements Identifiable {

    private final String ID;

    private final String jcaName;

    private Provider provider; // default, if any

    CryptoAlgorithm(String id, String jcaName) {
        Assert.hasText(id, "id cannot be null or empty.");
        this.ID = id;
        Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.jcaName = jcaName;
    }

    @Override
    public String getId() {
        return this.ID;
    }

    String getJcaName() {
        return this.jcaName;
    }

    protected void setProvider(Provider provider) { // can be null
        this.provider = provider;
    }

    protected Provider getProvider() {
        return this.provider;
    }

    SecureRandom ensureSecureRandom(Request<?> request) {
        SecureRandom random = request != null ? request.getSecureRandom() : null;
        return random != null ? random : Randoms.secureRandom();
    }

    protected <T, R> R execute(Class<T> clazz, CheckedFunction<T, R> fn) {
        return new JcaTemplate(getJcaName(), this.provider).execute(clazz, fn);
    }

    protected Provider getProvider(Request<?> request) {
        Provider provider = request.getProvider();
        if (provider == null) {
            provider = this.provider; // fallback, if any
        }
        return provider;
    }

    protected <I, T> T execute(Request<?> request, Class<I> clazz, CheckedFunction<I, T> fn) {
        Assert.notNull(request, "request cannot be null.");
        Provider provider = getProvider(request);
        SecureRandom random = ensureSecureRandom(request);
        JcaTemplate template = new JcaTemplate(getJcaName(), provider, random);
        return template.execute(clazz, fn);
    }

    public SecretKey generateKey(KeyRequest<?> request) {
        AeadAlgorithm enc = Assert.notNull(request.getEncryptionAlgorithm(), "Request encryptionAlgorithm cannot be null.");
        SecretKeyBuilder builder = Assert.notNull(enc.keyBuilder(), "Request encryptionAlgorithm keyBuilder cannot be null.");
        SecretKey key = builder.setProvider(getProvider(request)).setRandom(request.getSecureRandom()).build();
        return Assert.notNull(key, "Request encryptionAlgorithm SecretKeyBuilder cannot produce null keys.");
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof CryptoAlgorithm) {
            CryptoAlgorithm other = (CryptoAlgorithm) obj;
            return this.ID.equals(other.getId()) && this.jcaName.equals(other.getJcaName());
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + ID.hashCode();
        hash = 31 * hash + jcaName.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        return ID;
    }
}
