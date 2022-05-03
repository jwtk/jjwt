package io.jsonwebtoken.impl.security

import java.security.interfaces.RSAPrivateKey

class TestRSAPrivateKey<T extends RSAPrivateKey> extends TestRSAKey<T> implements RSAPrivateKey {

    TestRSAPrivateKey(T key) {
        super(key)
    }

    @Override
    BigInteger getPrivateExponent() {
        return src.privateExponent
    }
}
