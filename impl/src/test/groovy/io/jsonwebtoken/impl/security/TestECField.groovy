package io.jsonwebtoken.impl.security

import java.security.spec.ECField

class TestECField implements ECField {

    int fieldSize

    @Override
    int getFieldSize() {
        return fieldSize
    }
}
