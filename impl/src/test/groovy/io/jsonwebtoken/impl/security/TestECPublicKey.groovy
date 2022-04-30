package io.jsonwebtoken.impl.security

import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint

class TestECPublicKey extends TestECKey implements ECPublicKey {

    ECPoint w

    @Override
    ECPoint getW() {
        return w
    }
}
