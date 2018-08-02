package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.EncryptionAlgorithm;
import io.jsonwebtoken.security.EncryptionResult;

import java.security.Key;

abstract class AbstractEncryptionAlgorithm<T, E extends Key, D extends Key, EReq extends CryptoRequest<T, E>,
    ERes extends EncryptionResult, DReq extends CryptoRequest<T, D>>
    extends CipherAlgorithm implements EncryptionAlgorithm<T, E, D, EReq, ERes, DReq> {

    AbstractEncryptionAlgorithm(String name, String transformationString) {
        super(name, transformationString);
    }

    @Override
    public ERes encrypt(EReq req) throws CryptoException {
        try {
            Assert.notNull(req, "Encryption request cannot be null.");
            return doEncrypt(req);
        } catch (CryptoException ce) {
            throw ce; //propagate
        } catch (Exception e) {
            String msg = "Unable to perform " + getName() + " encryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected abstract ERes doEncrypt(EReq req) throws Exception;

    @Override
    public byte[] decrypt(DReq req) throws CryptoException {
        try {
            Assert.notNull(req, "Decryption request cannot be null.");
            return doDecrypt(req);
        } catch (CryptoException ce) {
            throw ce; //propagate
        } catch (Exception e) {
            String msg = "Unable to perform " + getName() + " decryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected abstract byte[] doDecrypt(DReq req) throws Exception;
}
