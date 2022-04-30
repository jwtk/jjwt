package io.jsonwebtoken.impl.security

import java.security.interfaces.ECPrivateKey

class TestECPrivateKey extends TestECKey implements ECPrivateKey {

    BigInteger s

    @Override
    BigInteger getS() {
        return s
    }
}
