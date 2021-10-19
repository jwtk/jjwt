package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

class RsaPublicJwkFactory extends AbstractFamilyJwkFactory<RSAPublicKey, RsaPublicJwk> {

    static final RsaPublicJwkFactory DEFAULT_INSTANCE = new RsaPublicJwkFactory();

    RsaPublicJwkFactory() {
        super(DefaultRsaPublicJwk.TYPE_VALUE, RSAPublicKey.class);
    }

    @Override
    protected RsaPublicJwk createJwkFromKey(JwkContext<RSAPublicKey> ctx) {
        RSAPublicKey key = ctx.getKey();
        ctx.put(DefaultRsaPublicJwk.MODULUS.getId(), encode(key.getModulus()));
        ctx.put(DefaultRsaPublicJwk.PUBLIC_EXPONENT.getId(), encode(key.getPublicExponent()));
        return new DefaultRsaPublicJwk(ctx);
    }

    @Override
    protected RsaPublicJwk createJwkFromValues(JwkContext<RSAPublicKey> ctx) {
        ValueGetter getter = new DefaultValueGetter(ctx);
        BigInteger modulus = getter.getRequiredBigInt(DefaultRsaPublicJwk.MODULUS.getId(), false);
        BigInteger publicExponent = getter.getRequiredBigInt(DefaultRsaPublicJwk.PUBLIC_EXPONENT.getId(), false);
        final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);

        RSAPublicKey key = generateKey(ctx, new CheckedFunction<KeyFactory, RSAPublicKey>() {
            @Override
            public RSAPublicKey apply(KeyFactory keyFactory) throws Exception {
                return (RSAPublicKey) keyFactory.generatePublic(spec);
            }
        });

        ctx.setKey(key);

        return new DefaultRsaPublicJwk(ctx);
    }
}
