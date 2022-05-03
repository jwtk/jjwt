package io.jsonwebtoken.impl.security

import java.security.Key
import java.security.interfaces.RSAKey

class TestRSAKey<T extends RSAKey & Key> implements RSAKey, Key {

    final T src

    TestRSAKey(T key) {
        this.src = key
    }

    @Override
    String getAlgorithm() {
        return src.getAlgorithm()
    }

    @Override
    String getFormat() {
        return src.getFormat()
    }

    @Override
    byte[] getEncoded() {
        return src.getEncoded()
    }

    @Override
    BigInteger getModulus() {
        return src.getModulus()
    }
}
