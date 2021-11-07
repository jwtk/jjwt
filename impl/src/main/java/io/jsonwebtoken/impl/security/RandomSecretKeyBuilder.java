package io.jsonwebtoken.impl.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class RandomSecretKeyBuilder extends DefaultSecretKeyBuilder {

    public RandomSecretKeyBuilder(String jcaName, int bitLength) {
        super(jcaName, bitLength);
    }

    @Override
    public SecretKey build() {
        byte[] bytes = new byte[this.BIT_LENGTH / Byte.SIZE];
        this.random.nextBytes(bytes);
        return new SecretKeySpec(bytes, this.JCA_NAME);
    }
}
