package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.AbstractParser;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyOperationPolicy;

import java.security.Provider;
import java.util.Map;

abstract class AbstractJwkParser<T> extends AbstractParser<T> {

    protected final KeyOperationPolicy operationPolicy;

    public AbstractJwkParser(Provider provider, Deserializer<Map<String, ?>> deserializer, KeyOperationPolicy policy) {
        super(provider, deserializer);
        Assert.notNull(policy, "KeyOperationPolicy cannot be null.");
        Assert.notEmpty(policy.getOperations(), "KeyOperationPolicy's operations cannot be null or empty.");
        this.operationPolicy = policy;
    }

}
