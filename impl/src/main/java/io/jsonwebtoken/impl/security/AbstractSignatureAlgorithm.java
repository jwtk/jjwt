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

abstract class AbstractSignatureAlgorithm<SK extends Key, VK extends Key> extends CryptoAlgorithm implements SignatureAlgorithm<SK, VK> {

    AbstractSignatureAlgorithm(String id, String jcaName) {
        super(id, jcaName);
    }

    protected static String keyType(boolean signing) {
        return signing ? "signing" : "verification";
    }

    protected abstract void validateKey(Key key, boolean signing);

    @Override
    public byte[] sign(SignatureRequest<SK> request) throws SecurityException {
        final SK key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        Assert.notEmpty(request.getContent(), "Request content cannot be null or empty.");
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

    protected abstract byte[] doSign(SignatureRequest<SK> request) throws Exception;

    @Override
    public boolean verify(VerifySignatureRequest<VK> request) throws SecurityException {
        final VK key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        Assert.notEmpty(request.getContent(), "Request content cannot be null or empty.");
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

    protected boolean doVerify(VerifySignatureRequest<VK> request) throws Exception {
        byte[] providedSignature = request.getDigest();
        Assert.notEmpty(providedSignature, "Request signature byte array cannot be null or empty.");
        @SuppressWarnings("unchecked") byte[] computedSignature = sign((SignatureRequest<SK>)request);
        return MessageDigest.isEqual(providedSignature, computedSignature);
    }
}
