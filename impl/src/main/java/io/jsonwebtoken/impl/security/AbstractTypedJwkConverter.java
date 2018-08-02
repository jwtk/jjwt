package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;

import java.security.KeyFactory;
import java.util.HashMap;
import java.util.Map;

abstract class AbstractTypedJwkConverter extends AbstractJwkConverter implements TypedJwkConverter {

    private final String keyType;

    AbstractTypedJwkConverter(String keyType) {
        Assert.hasText(keyType, "keyType argument cannot be null or empty.");
        this.keyType = keyType;
    }

    @Override
    public String getKeyType() {
        return this.keyType;
    }

    KeyFactory getKeyFactory() {
        return getKeyFactory(getKeyType());
    }

    Map<String,String> newJwkMap() {
        Map<String,String> m = new HashMap<>();
        m.put("kty", getKeyType());
        return m;
    }

}
