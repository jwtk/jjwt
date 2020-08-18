package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PayloadSupplier;

import java.security.Key;

class DefaultPayloadSupplier<T> implements PayloadSupplier<T> {

    private final T payload;

    DefaultPayloadSupplier(T payload) {
        this.payload = Assert.notNull(payload, "payload cannot be null.");
        Assert.isTrue(payload instanceof byte[] || payload instanceof Key, "Payload argument must be either a byte array or a java.security.Key.");
        if (payload instanceof byte[] && ((byte[]) payload).length == 0) {
            throw new IllegalArgumentException("Payload byte array cannot be empty.");
        }
    }

    @Override
    public T getPayload() {
        return payload;
    }
}
