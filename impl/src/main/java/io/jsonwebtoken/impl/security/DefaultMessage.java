package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Message;

class DefaultMessage<T> implements Message<T> {

    private final T payload;

    DefaultMessage(T payload) {
        this.payload = Assert.notNull(payload, "payload cannot be null.");
        if (payload instanceof byte[]) {
            assertBytePayload((byte[])payload);
        }
    }
    protected void assertBytePayload(byte[] payload) {
        Assert.notEmpty(payload, "payload byte array cannot be null or empty.");
    }

    @Override
    public T getPayload() {
        return payload;
    }
}
