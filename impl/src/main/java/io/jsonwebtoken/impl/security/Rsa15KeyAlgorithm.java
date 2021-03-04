package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

public class Rsa15KeyAlgorithm<EK extends RSAKey & PublicKey, DK extends RSAKey & PrivateKey> implements EncryptedKeyAlgorithm<EK, DK> {

    private static final String ID = "RSA1_5";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<SecretKey, EK> request) throws SecurityException {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], DK> request) throws SecurityException {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
