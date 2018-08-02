package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySignatureRequest;

public class NoneSignatureAlgorithm implements SignatureAlgorithm {

    private static final String NAME = "none";

    @Override
    public String getName() {
        return NAME;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public byte[] sign(CryptoRequest request) throws SignatureException {
        throw new SignatureException("The 'none' algorithm cannot be used to create signatures.");
    }

    @Override
    public boolean verify(VerifySignatureRequest request) throws SignatureException {
        throw new SignatureException("The 'none' algorithm cannot be used to verify signatures.");
    }
}
