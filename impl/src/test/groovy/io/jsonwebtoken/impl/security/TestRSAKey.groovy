package io.jsonwebtoken.impl.security

import java.security.interfaces.RSAKey

class TestRSAKey extends TestKey implements RSAKey {

    final def src

    TestRSAKey(def key) {
        this.src = key
    }

    @Override
    String getAlgorithm() {
        return src.algorithm
    }

    @Override
    String getFormat() {
        return src.format
    }

    @Override
    byte[] getEncoded() {
        return src.encoded
    }

    @Override
    BigInteger getModulus() {
        return src.getModulus()
    }
}
