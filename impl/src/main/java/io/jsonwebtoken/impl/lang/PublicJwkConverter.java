package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.SecretJwk;

import java.util.Map;

@SuppressWarnings("rawtypes")
public class PublicJwkConverter implements Converter<PublicJwk, Object> {

    @Override
    public Object applyTo(PublicJwk publicJwk) {
        return publicJwk;
    }

    @Override
    public PublicJwk<?> applyFrom(Object o) {
        Assert.notNull(o, "JWK argument cannot be null.");
        if (o instanceof PublicJwk<?>) {
            return ((PublicJwk<?>) o);
        }
        if (o instanceof Map) {
            Map<?,?> map = (Map<?, ?>) o;
            JwkBuilder<?,?,?> builder = Jwks.builder();
            for(Map.Entry<?,?> entry : map.entrySet()) {
                Object key = entry.getKey();
                Assert.notNull(key, "JWK map key cannot be null.");
                if (!(key instanceof String)) {
                    String msg = "Unsupported 'jwk' map value - all JWK map keys must be Strings.  Encountered key '" +
                            key + "' of type " + key.getClass().getName();
                    throw new IllegalArgumentException(msg);
                }
                String skey = (String)key;
                builder.put(skey, entry.getValue());
            }
            Jwk<?> jwk = builder.build();
            if (!(jwk instanceof PublicJwk<?>)) {
                String type;
                if (jwk instanceof SecretJwk) {
                    type = "SecretJwk";
                } else {
                    // only other type remaining:
                    Assert.isInstanceOf(PrivateJwk.class, jwk, "Unexpected Jwk type - programming error. Please report this to the JJWT team.");
                    type = "PrivateJwk";
                }
                String msg = "Unsupported JWK map - JWK values must represent a PublicJwk, not a " + type + ".";
                throw new IllegalArgumentException(msg);
            }
            return ((PublicJwk<?>) jwk);
        }
        String msg = "Unsupported value type - expected a Map or Jwk instance.  Type found: " +
                o.getClass().getName();
        throw new IllegalArgumentException(msg);
    }
}
