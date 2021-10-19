package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
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
        ctx.put(DefaultSecretJwk.K.getId(), k);

        return new DefaultSecretJwk(ctx);
    }

    @Override
    protected SecretJwk createJwkFromValues(JwkContext<SecretKey> ctx) {
        ValueGetter getter = new DefaultValueGetter(ctx);
        byte[] bytes = getter.getRequiredBytes(DefaultSecretJwk.K.getId());
        SecretKey key = new SecretKeySpec(bytes, "NONE"); //TODO: do we need a JCA-specific ID here?
        ctx.setKey(key);
        return new DefaultSecretJwk(ctx);
    }
}
