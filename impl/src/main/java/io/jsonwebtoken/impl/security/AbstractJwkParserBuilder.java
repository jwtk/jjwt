package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.io.AbstractParserBuilder;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.JwkParserBuilder;
import io.jsonwebtoken.security.KeyOperationPolicy;

abstract class AbstractJwkParserBuilder<T, B extends JwkParserBuilder<T, B>>
        extends AbstractParserBuilder<T, B> implements JwkParserBuilder<T, B> {

    protected KeyOperationPolicy operationPolicy = AbstractJwkBuilder.DEFAULT_OPERATION_POLICY;

    @Override
    public B operationPolicy(KeyOperationPolicy policy) throws IllegalArgumentException {
        Assert.notNull(policy, "KeyOperationPolicy may not be null.");
        Assert.notEmpty(policy.getOperations(), "KeyOperationPolicy's operations may not be null or empty.");
        this.operationPolicy = policy;
        return self();
    }

}
