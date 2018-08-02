package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoRequest;

abstract class CipherAlgorithm extends CryptoAlgorithm {

    private final String transformation;

    CipherAlgorithm(String name, String transformation) {
        super(name, transformation);
        Assert.hasText(transformation, "Transformation string cannot be null or empty.");
        this.transformation = transformation;
    }

    CipherTemplate newCipherTemplate(CryptoRequest request) {
        return new CipherTemplate(this.transformation, request != null ? request.getProvider() : null);
    }
}
