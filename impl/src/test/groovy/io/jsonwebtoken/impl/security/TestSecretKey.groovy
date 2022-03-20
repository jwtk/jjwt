package io.jsonwebtoken.impl.security

import javax.crypto.SecretKey

class TestSecretKey implements SecretKey {

    private String algorithm
    private String format
    private byte[] encoded

    @Override
    String getAlgorithm() {
        return this.algorithm
    }

    @Override
    String getFormat() {
        return this.format
    }

    @Override
    byte[] getEncoded() {
        return this.encoded
    }
}
