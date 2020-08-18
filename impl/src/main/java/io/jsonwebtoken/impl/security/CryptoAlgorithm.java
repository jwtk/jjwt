package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SecurityRequest;

import java.security.Provider;
import java.security.SecureRandom;

abstract class CryptoAlgorithm implements Identifiable {

    private final String ID;

    private final String jcaName;

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

    SecureRandom ensureSecureRandom(SecurityRequest request) {
        SecureRandom random = request != null ? request.getSecureRandom() : null;
        return random != null ? random : Randoms.secureRandom();
    }

    protected <T, R> R execute(Class<T> clazz, CheckedFunction<T, R> fn) {
        return new JcaTemplate(getJcaName(), null).execute(clazz, fn);
    }

    protected <I, T> T execute(SecurityRequest request, Class<I> clazz, CheckedFunction<I, T> fn) {
        Assert.notNull(request, "request cannot be null.");
        Provider provider = request.getProvider();
        SecureRandom random = ensureSecureRandom(request);
        JcaTemplate template = new JcaTemplate(getJcaName(), provider, random);
        return template.execute(clazz, fn);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof CryptoAlgorithm) {
            CryptoAlgorithm other = (CryptoAlgorithm)obj;
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
