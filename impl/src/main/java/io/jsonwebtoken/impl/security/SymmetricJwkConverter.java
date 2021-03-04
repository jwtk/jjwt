package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class SymmetricJwkConverter extends AbstractTypedJwkConverter {

    public SymmetricJwkConverter() {
        super("oct");
    }

    @Override
    public boolean supports(Key key) {
        return key instanceof SecretKey;
    }

    @Override
    public Map<String, String> toJwk(Key key) {
        String k;
        try {
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length == 0) {
                throw new IllegalArgumentException("SecretKey argument does not have any encoded bytes.");
            }
            k = Encoders.BASE64URL.encode(encoded);
        } catch (Exception e) {
            String msg = "Unable to encode secret key to JWK.";
            throw new UnsupportedKeyException(msg, e);
        }

        Map<String,String> m = new HashMap<>();
        m.put("kty", "oct");
        m.put("k", k);

        return m;
    }

    @Override
    public SecretKey toKey(Map<String, ?> jwk) {
        String oct = getRequiredString(jwk, "oct");
        byte[] bytes;
        try {
            bytes = Decoders.BASE64URL.decode(oct);
        } catch (DecodingException e) {
            String msg = "Unable to Base64Url-decode JWK 'oct' member value: " + oct;
            throw new MalformedKeyException(msg, e);
        }
        return new SecretKeySpec(bytes, "AES"); //TODO: what about other algorithms?
    }
}
