package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PayloadSupplier;

import java.security.Key;

class DefaultPayloadSupplier<T> implements PayloadSupplier<T> {

    private final T payload;

    DefaultPayloadSupplier(T payload) {
        this.payload = assertValidPayload(payload);
    }

    protected T assertValidPayload(T payload) throws IllegalArgumentException {
        Assert.notNull(payload, "payload cannot be null.");
        if (payload instanceof byte[]) {
            Assert.notEmpty((byte[])payload, "payload byte array cannot be empty.");
        } else if (!(payload instanceof Key)) {
            String msg = "payload must be either a byte array or a java.security.Key instance.";
            throw new IllegalArgumentException(msg);
        }
        return payload;
    }

    @Override
    public T getPayload() {
        return payload;
    }
}
