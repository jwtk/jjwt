package io.jsonwebtoken.impl.security

import java.security.interfaces.RSAPrivateKey

class TestRSAPrivateKey extends TestRSAKey implements RSAPrivateKey {

    TestRSAPrivateKey(RSAPrivateKey key) {
        super(key)
    }

    @Override
    BigInteger getPrivateExponent() {
        return src.privateExponent
    }
}
