package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.KeyPairGenerator;

import java.security.KeyPair;

public class EllipticCurveKeyPairGenerator implements KeyPairGenerator {
    @Override
    public boolean supports(SignatureAlgorithm alg) {
        return alg.isEllipticCurve();
    }

    @Override
    public KeyPair generateKeyPair(SignatureAlgorithm alg) {
        return EllipticCurveProvider.generateKeyPair(alg);
    }
}
