package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.VerifySignatureRequest;

import java.security.Key;

public class NoneSignatureAlgorithm implements SignatureAlgorithm<Key, Key> {

    private static final String ID = "none";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public byte[] sign(SignatureRequest<Key> request) throws SecurityException {
        throw new SignatureException("The 'none' algorithm cannot be used to create signatures.");
    }

    @Override
    public boolean verify(VerifySignatureRequest<Key> request) throws SignatureException {
        throw new SignatureException("The 'none' algorithm cannot be used to verify signatures.");
    }

    @Override
    public boolean equals(Object obj) {
        return this == obj ||
            (obj instanceof SignatureAlgorithm && ID.equalsIgnoreCase(((SignatureAlgorithm<?, ?>) obj).getId()));
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }
}
