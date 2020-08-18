package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.PayloadSupplier;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.SecurityException;

import java.security.Key;

abstract class AbstractEncryptionAlgorithm<T, E extends Key, D extends Key,
    EReq extends CryptoRequest<T, E>, ERes extends PayloadSupplier<byte[]>,
    DReq extends CryptoRequest<byte[], D>, DRes extends PayloadSupplier<T>>
    extends CryptoAlgorithm implements EncryptionAlgorithm<T, E, D, EReq, ERes, DReq, DRes> {

    AbstractEncryptionAlgorithm(String id, String transformationString) {
        super(id, transformationString);
    }

    @Override
    public ERes encrypt(EReq req) throws CryptoException {
        try {
            Assert.notNull(req, "Encryption request cannot be null.");
            return doEncrypt(req);
        } catch (SecurityException se) {
            throw se; //propagate
        } catch (Exception e) {
            String msg = "Unable to perform " + getId() + " encryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected abstract ERes doEncrypt(EReq req) throws Exception;

    @Override
    public DRes decrypt(DReq req) throws CryptoException, KeyException {
        try {
            Assert.notNull(req, "Decryption request cannot be null.");
            byte[] bytes = doDecrypt(req);
            //noinspection unchecked
            return (DRes) new DefaultPayloadSupplier<>(bytes);
        } catch (SecurityException se) {
            throw se; //propagate
        } catch (Exception e) {
            String msg = "Unable to perform " + getId() + " decryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected abstract byte[] doDecrypt(DReq req) throws Exception;
}
