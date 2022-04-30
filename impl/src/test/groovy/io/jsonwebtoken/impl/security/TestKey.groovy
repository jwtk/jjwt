package io.jsonwebtoken.impl.security

import java.security.Key

class TestKey implements Key {

    String algorithm
    String format
    byte[] encoded

    @Override
    String getAlgorithm() {
        return algorithm
    }

    @Override
    String getFormat() {
        return format
    }

    @Override
    byte[] getEncoded() {
        return encoded
    }
}
