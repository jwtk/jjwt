package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.Named;

public interface EncryptionAlgorithm extends Named {

    EncryptionResult encrypt(EncryptionRequest request) throws CryptoException;

    byte[] decrypt(DecryptionRequest request) throws CryptoException;
}
