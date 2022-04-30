package io.jsonwebtoken.impl.security

import java.security.interfaces.ECKey
import java.security.spec.ECParameterSpec

class TestECKey extends TestKey implements ECKey {

    ECParameterSpec params

    @Override
    ECParameterSpec getParams() {
        return params
    }
}
