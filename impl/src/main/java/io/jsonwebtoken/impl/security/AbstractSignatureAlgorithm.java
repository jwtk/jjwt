package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySignatureRequest;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

abstract class AbstractSignatureAlgorithm extends CryptoAlgorithm implements SignatureAlgorithm {

    AbstractSignatureAlgorithm(String name, String jcaName) {
        super(name, jcaName);
    }

    //visible for testing
    protected boolean isBouncyCastleAvailable() {
        return RuntimeEnvironment.BOUNCY_CASTLE_AVAILABLE;
    }

    protected Signature createSignatureInstance(Provider provider, AlgorithmParameterSpec spec) {

        Signature sig;
        try {
            sig = getSignatureInstance(provider);
        } catch (NoSuchAlgorithmException e) {

            String msg = "JWT signature algorithm '" + getName() + "' uses the JCA algorithm '" + getJcaName() +
                "', which is not ";

            if (provider != null) {
                msg += "supported by the specified JCA Provider {" + provider + "}. Try ";
            } else {
                msg += "available in the current JVM. Try ";
            }

            if (!isBouncyCastleAvailable()) {
                msg += "including BouncyCastle in the runtime classpath, or ";
            }

            msg += "explicitly supplying a JCA Provider that supports the JCA algorithm name '" + getJcaName() +
                "'. Cause: " + e.getMessage();

            throw new SignatureException(msg, e);
        }

        if (spec != null) {
            try {
                setParameter(sig, spec);
            } catch (InvalidAlgorithmParameterException e) {
                String msg = "Unsupported " + getJcaName() + " parameter {" + spec + "}: " + e.getMessage();
                throw new SignatureException(msg, e);
            }
        }

        return sig;
    }

    //for testing overrides
    protected Signature getSignatureInstance(Provider provider) throws NoSuchAlgorithmException {
        final String jcaName = getJcaName();
        return provider != null ?
            Signature.getInstance(jcaName, provider) :
            Signature.getInstance(jcaName);
    }

    //for testing overrides
    protected void setParameter(Signature sig, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
        sig.setParameter(spec);
    }

    protected static String keyType(boolean signing) {
        return signing ? "signing" : "verification";
    }

    protected abstract void validateKey(Key key, boolean signing);

    @Override
    public byte[] sign(CryptoRequest<byte[], Key> request) throws SignatureException, KeyException {
        final Key key = Assert.notNull(request.getKey(), "Signature request key cannot be null.");
        Assert.notEmpty(request.getData(), "Signature request data byte array cannot be null or empty.");
        try {
            validateKey(key, true);
            return doSign(request);
        } catch (SignatureException | KeyException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to compute " + getName() + " signature with JCA algorithm '" + getJcaName() + "' " +
                "using key {" + key + "}: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected abstract byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception;

    @Override
    public boolean verify(VerifySignatureRequest request) throws SignatureException, KeyException {
        final Key key = Assert.notNull(request.getKey(), "Signature verification key cannot be null.");
        Assert.notEmpty(request.getData(), "Signature verification data byte array cannot be null or empty.");
        Assert.notEmpty(request.getSignature(), "Signature byte array cannot be null or empty.");
        try {
            validateKey(key, false);
            return doVerify(request);
        } catch (SignatureException | KeyException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to verify " + getName() + " signature with JCA algorithm '" + getJcaName() + "' " +
                "using key {" + key + "}: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected boolean doVerify(VerifySignatureRequest request) throws Exception {
        byte[] providedSignature = request.getSignature();
        Assert.notEmpty(providedSignature, "Request signature byte array cannot be null or empty.");
        byte[] computedSignature = sign(request);
        return MessageDigest.isEqual(providedSignature, computedSignature);
    }
}
