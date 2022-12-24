package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.Provider;

class DefaultCurve implements Curve {

    private final String ID;

    private final String JCA_NAME;

    private final Provider PROVIDER; // can be null

    DefaultCurve(String id, String jcaName) {
        this(id, jcaName, null);
    }

    DefaultCurve(String id, String jcaName, Provider provider) {
        this.ID = Assert.notNull(Strings.clean(id), "Curve ID cannot be null or empty.");
        this.JCA_NAME = Assert.notNull(Strings.clean(jcaName), "Curve jcaName cannot be null or empty.");
        this.PROVIDER = provider;
    }

    @Override
    public String getId() {
        return this.ID;
    }

    public String getJcaName() {
        return this.JCA_NAME;
    }

    @Override
    public int hashCode() {
        return ID.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Curve) {
            Curve curve = (Curve) obj;
            return ID.equals(curve.getId());
        }
        return false;
    }

    @Override
    public String toString() {
        return ID;
    }

    public KeyPairBuilder keyPairBuilder() {
        return new DefaultKeyPairBuilder(this.JCA_NAME).setProvider(this.PROVIDER);
    }
}
