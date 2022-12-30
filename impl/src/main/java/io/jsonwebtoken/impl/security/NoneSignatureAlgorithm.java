package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.security.Key;

public class NoneSignatureAlgorithm implements SecureDigestAlgorithm<Key, Key> {

    private static final String ID = "none";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public byte[] digest(SecureRequest<byte[], Key> request) throws SecurityException {
        throw new SignatureException("The 'none' algorithm cannot be used to create signatures.");
    }

    @Override
    public boolean verify(VerifySecureDigestRequest<Key> request) throws SignatureException {
        throw new SignatureException("The 'none' algorithm cannot be used to verify signatures.");
    }

    @Override
    public boolean equals(Object obj) {
        return this == obj ||
                (obj instanceof SecureDigestAlgorithm &&
                        ID.equalsIgnoreCase(((SecureDigestAlgorithm<?, ?>) obj).getId()));
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    @Override
    public String toString() {
        return ID;
    }
}
