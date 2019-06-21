package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.KeyPairGenerator;

import java.security.KeyPair;

public class RsaKeyPairGenerator implements KeyPairGenerator {
    @Override
    public boolean supports(SignatureAlgorithm alg) {
        return alg.isRsa();
    }

    @Override
    public KeyPair generateKeyPair(SignatureAlgorithm alg) {
        return RsaProvider.generateKeyPair(alg);
    }
}
