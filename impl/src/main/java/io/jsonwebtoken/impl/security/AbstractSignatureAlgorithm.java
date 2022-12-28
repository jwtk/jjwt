package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.VerifySignatureRequest;

import java.security.Key;
import java.security.MessageDigest;

abstract class AbstractSignatureAlgorithm<S extends Key, V extends Key> extends CryptoAlgorithm implements SignatureAlgorithm<S, V> {

    AbstractSignatureAlgorithm(String id, String jcaName) {
        super(id, jcaName);
    }

    protected static String keyType(boolean signing) {
        return signing ? "signing" : "verification";
    }

    protected abstract void validateKey(Key key, boolean signing);

    @Override
    public byte[] sign(SignatureRequest<S> request) throws SecurityException {
        final S key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        Assert.notEmpty(request.getPayload(), "Request content cannot be null or empty.");
        try {
            validateKey(key, true);
            return doSign(request);
        } catch (SignatureException | KeyException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to compute " + getId() + " signature with JCA algorithm '" + getJcaName() + "' " +
                    "using key {" + key + "}: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected abstract byte[] doSign(SignatureRequest<S> request) throws Exception;

    @Override
    public boolean verify(VerifySignatureRequest<V> request) throws SecurityException {
        final V key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        Assert.notEmpty(request.getPayload(), "Request content cannot be null or empty.");
        Assert.notEmpty(request.getDigest(), "Request signature byte array cannot be null or empty.");
        try {
            validateKey(key, false);
            return doVerify(request);
        } catch (SignatureException | KeyException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to verify " + getId() + " signature with JCA algorithm '" + getJcaName() + "' " +
                    "using key {" + key + "}: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected boolean doVerify(VerifySignatureRequest<V> request) throws Exception {
        byte[] providedSignature = request.getDigest();
        Assert.notEmpty(providedSignature, "Request signature byte array cannot be null or empty.");
        @SuppressWarnings("unchecked") byte[] computedSignature = sign((SignatureRequest<S>) request);
        return MessageDigest.isEqual(providedSignature, computedSignature);
    }
}
