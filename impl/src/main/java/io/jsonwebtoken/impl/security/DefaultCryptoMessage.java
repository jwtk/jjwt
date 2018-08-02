package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoMessage;

import java.security.Key;
import java.security.Provider;

class DefaultCryptoMessage<T> implements CryptoMessage<T> {

    private final T data;

    DefaultCryptoMessage(T data) {
        this.data = Assert.notNull(data, "data cannot be null.");
        if (data instanceof byte[] && ((byte[]) data).length == 0) {
            throw new IllegalArgumentException("data byte array cannot be empty.");
        }
    }

    @Override
    public T getData() {
        return data;
    }
}
