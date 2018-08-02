package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.SymmetricJwk;

final class DefaultSymmetricJwk extends AbstractJwk<SymmetricJwk> implements SymmetricJwk {

    static final String TYPE_VALUE = "oct";
    static final String K = "k";

    DefaultSymmetricJwk() {
        super(TYPE_VALUE);
    }

    @Override
    public String getK() {
        return getString(K);
    }

    @Override
    public SymmetricJwk setK(String k) {
        k = Strings.clean(k);
        Assert.notNull(k, "SymmetricJwk 'k' property cannot be null or empty.");
        setValue(K, k);
        return this;
    }
}
