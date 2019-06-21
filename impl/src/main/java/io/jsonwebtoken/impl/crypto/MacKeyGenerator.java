package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.KeyGenerator;

import javax.crypto.SecretKey;

public final class MacKeyGenerator implements KeyGenerator {

    @Override
    public boolean supports(SignatureAlgorithm alg) {
        return alg.isHmac();
    }

    @Override
    public SecretKey generateKey(SignatureAlgorithm alg) {
        return MacProvider.generateKey(alg);
    }
}
