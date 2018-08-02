package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

class CipherTemplate {

    private final Provider provider;

    private final String transformation;

    CipherTemplate(String transformation, Provider provider) {
        Assert.hasText(transformation, "Transformation string cannot be null or empty.");
        this.transformation = transformation;
        this.provider = provider;
    }

    //for testing visibility
    Cipher getCipherInstance(String transformation, Provider provider)
        throws NoSuchPaddingException, NoSuchAlgorithmException {
        return provider != null ?
            Cipher.getInstance(transformation, provider) :
            Cipher.getInstance(transformation);
    }

    private Cipher newCipher() throws CryptoException {
        try {
            return getCipherInstance(transformation, provider);
        } catch (Exception e) {
            String msg = "Unable to obtain cipher from ";
            if (provider != null) {
                msg += "specified Provider {" + provider + "} ";
            } else {
                msg += "default JCA Provider ";
            }
            msg += "for transformation '" + transformation + "': " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    <T> T execute(CipherCallback<T> callback) throws CryptoException {
        Cipher cipher = newCipher();
        try {
            return callback.doWithCipher(cipher);
        } catch (Exception e) {
            throw new CryptoException("Cipher callback execution failed: " + e.getMessage(), e);
        }
    }
}
