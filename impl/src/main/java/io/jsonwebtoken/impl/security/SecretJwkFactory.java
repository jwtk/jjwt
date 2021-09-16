package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class SecretJwkFactory extends AbstractFamilyJwkFactory<SecretKey, SecretJwk> {

    SecretJwkFactory() {
        super(DefaultSecretJwk.TYPE_VALUE, SecretKey.class);
    }

    static byte[] getRequiredEncoded(SecretKey key, String reason) {
        Assert.notNull(key, "SecretKey argument cannot be null.");
        Assert.hasText(reason, "Reason string argument cannot be null or empty.");
        byte[] encoded = null;
        Exception cause = null;
        try {
            encoded = key.getEncoded();
        } catch (Exception e) {
            cause = e;
        }

        if (Arrays.length(encoded) == 0) {
            String msg = "SecretKey argument does not have any encoded bytes, or the key's backing JCA Provider " +
                "is preventing key.getEncoded() from returning any bytes.  In either case, it is not possible to " +
                reason + ".";
            throw new UnsupportedKeyException(msg, cause);
        }

        return encoded;
    }

    @Override
    protected SecretJwk createJwkFromKey(JwkContext<SecretKey> ctx) {
        SecretKey key = Assert.notNull(ctx.getKey(), "JwkContext key cannot be null.");
        String k;
        try {
            byte[] encoded = getRequiredEncoded(key, "represent the SecretKey instance as a JWK");
            k = Encoders.BASE64URL.encode(encoded);
        } catch (Exception e) {
            String msg = "Unable to encode SecretKey to JWK: " + e.getMessage();
            throw new UnsupportedKeyException(msg, e);
        }

        assert k != null : "k value is mandatory.";
        ctx.put(DefaultSecretJwk.K, k);

        return new DefaultSecretJwk(ctx);
    }

    @Override
    protected SecretJwk createJwkFromValues(JwkContext<SecretKey> ctx) {
        String encoded = getRequiredString(ctx, DefaultSecretJwk.K);
        byte[] bytes;
        try {
            bytes = Decoders.BASE64URL.decode(encoded);
            if (Arrays.length(bytes) == 0) {
                throw new IllegalArgumentException("JWK 'k' member does not have any encoded bytes. JWK: {" + ctx + "}");
            }
        } catch (Exception e) {
            String msg = "Unable to Base64Url-decode " + DefaultSecretJwk.TYPE_VALUE +
                " JWK 'k' member value. JWK: {" + ctx + "}";
            throw new MalformedKeyException(msg, e);
        }
        SecretKey key = new SecretKeySpec(bytes, "NONE"); //TODO: do we need a JCA-specific ID here?
        ctx.setKey(key);
        return new DefaultSecretJwk(ctx);
    }
}
