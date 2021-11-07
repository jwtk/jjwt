package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.SecretKeyBuilder

import javax.crypto.SecretKey
import java.security.Provider
import java.security.SecureRandom

class FixedSecretKeyBuilder implements SecretKeyBuilder {

    final SecretKey key

    FixedSecretKeyBuilder(SecretKey key) {
        this.key = key
    }

    @Override
    SecretKey build() {
        return this.key
    }

    @Override
    SecretKeyBuilder setProvider(Provider provider) {
        return this
    }

    @Override
    SecretKeyBuilder setRandom(SecureRandom random) {
        return this
    }
}
