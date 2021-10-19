package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;

class EcPrivateJwkFactory extends AbstractEcJwkFactory<ECPrivateKey, EcPrivateJwk> {

    private static final String ECPUBKEY_ERR_MSG = "JwkContext publicKey must be an " + ECPublicKey.class.getName() + " instance.";

    EcPrivateJwkFactory() {
        super(ECPrivateKey.class);
    }

    @Override
    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return super.supportsKeyValues(ctx) && ctx.containsKey(DefaultEcPrivateJwk.D.getId());
    }

    @Override
    protected EcPrivateJwk createJwkFromKey(JwkContext<ECPrivateKey> ctx) {

        ECPrivateKey key = ctx.getKey();
        ECPublicKey ecPublicKey;

        PublicKey publicKey = ctx.getPublicKey();
        if (publicKey != null) {
            ecPublicKey = Assert.isInstanceOf(ECPublicKey.class, publicKey, ECPUBKEY_ERR_MSG);
        } else {
            ecPublicKey = derivePublic(ctx);
        }

        // [JWA spec](https://tools.ietf.org/html/rfc7518#section-6.2.2)
        // requires public values to be present in private JWKs, so add them:
        JwkContext<ECPublicKey> pubCtx = new DefaultJwkContext<>(DefaultEcPrivateJwk.PRIVATE_NAMES, ctx, ecPublicKey);
        EcPublicJwk pubJwk = EcPublicJwkFactory.DEFAULT_INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk); // add public values to private key context

        int fieldSize = key.getParams().getCurve().getField().getFieldSize();
        String d = toOctetString(fieldSize, key.getS());
        ctx.put(DefaultEcPrivateJwk.D.getId(), d);

        return new DefaultEcPrivateJwk(ctx, pubJwk);
    }

    @Override
    protected EcPrivateJwk createJwkFromValues(final JwkContext<ECPrivateKey> ctx) {

        ValueGetter getter = new DefaultValueGetter(ctx);
        String curveId = getter.getRequiredString(DefaultEcPublicJwk.CRV.getId());
        BigInteger d = getter.getRequiredBigInt(DefaultEcPrivateJwk.D.getId(), true);

        // We don't actually need the public x,y point coordinates for JVM lookup, but the
        // [JWA spec](https://tools.ietf.org/html/rfc7518#section-6.2.2)
        // requires them to be present and valid for the private key as well, so we assert that here:
        JwkContext<ECPublicKey> pubCtx = new DefaultJwkContext<>(DefaultEcPrivateJwk.PRIVATE_NAMES, ctx);
        EcPublicJwk pubJwk = EcPublicJwkFactory.DEFAULT_INSTANCE.createJwk(pubCtx);

        ECParameterSpec spec = getCurveByJwaId(curveId);
        final ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(d, spec);

        ECPrivateKey key = generateKey(ctx, new CheckedFunction<KeyFactory, ECPrivateKey>() {
            @Override
            public ECPrivateKey apply(KeyFactory kf) throws Exception {
                return (ECPrivateKey) kf.generatePrivate(privateSpec);
            }
        });

        ctx.setKey(key);

        return new DefaultEcPrivateJwk(ctx, pubJwk);
    }
}
