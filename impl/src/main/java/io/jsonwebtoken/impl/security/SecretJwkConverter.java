package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Map;

public class SecretJwkConverter extends AbstractJwkConverter<SecretKey> {

    static final SecretJwkConverter DEFAULT_INSTANCE = new SecretJwkConverter();

    public SecretJwkConverter() {
        super(DefaultSecretJwk.TYPE_VALUE);
    }

    @Override
    public boolean supports(Key key) {
        return key instanceof SecretKey;
    }

    @Override
    public Map<String, ?> applyTo(SecretKey key) {
        String k;
        try {
            byte[] encoded = key.getEncoded();
            if (Arrays.length(encoded) == 0) {
                throw new IllegalArgumentException("SecretKey argument does not have any encoded bytes, or " +
                    "the key's backing JCA Provider is preventing key.getEncoded() from returning any bytes.  In " +
                    "either case, it is not possible to represent the SecretKey instance as a JWK.");
            }
            k = Encoders.BASE64URL.encode(encoded);
        } catch (Exception e) {
            String msg = "Unable to encode SecretKey to JWK: " + e.getMessage();
            throw new UnsupportedKeyException(msg, e);
        }

        assert k != null : "k value is mandatory.";

        Map<String, Object> m = newJwkMap();
        m.put(DefaultSecretJwk.K, k);
        return m;
    }

    @Override
    public SecretKey applyFrom(Map<String, ?> jwk) {
        String encoded = getRequiredString(jwk, DefaultSecretJwk.K);
        byte[] bytes;
        try {
            bytes = Decoders.BASE64URL.decode(encoded);
            if (Arrays.length(bytes) == 0) {
                throw new IllegalArgumentException("JWK 'k' member does not have any encoded bytes. JWK: {" + jwk + "}");
            }
        } catch (Exception e) {
            Map<String,?> msgJwk = sanitize(jwk, DefaultSecretJwk.PRIVATE_NAMES);
            String msg = "Unable to Base64Url-decode 'oct' JWK 'k' member value. JWK: {" + msgJwk + "}";
            throw new MalformedKeyException(msg, e);
        }
        return new SecretKeySpec(bytes, "NONE"); //TODO: do we need JCA-specific IDs here?
    }
}
