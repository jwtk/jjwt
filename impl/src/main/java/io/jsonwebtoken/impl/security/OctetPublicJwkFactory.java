package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.RequiredFieldReader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.OctetPublicJwk;

import java.security.PublicKey;

public class OctetPublicJwkFactory extends OctetJwkFactory<PublicKey, OctetPublicJwk<PublicKey>> {

    static final OctetPublicJwkFactory INSTANCE = new OctetPublicJwkFactory();

    OctetPublicJwkFactory() {
        super(PublicKey.class, DefaultOctetPublicJwk.FIELDS);
    }

    @Override
    protected OctetPublicJwk<PublicKey> createJwkFromKey(JwkContext<PublicKey> ctx) {
        PublicKey key = Assert.notNull(ctx.getKey(), "PublicKey cannot be null.");
        EdwardsCurve crv = EdwardsCurve.forKey(key);
        byte[] x = crv.getKeyMaterial(key);
        Assert.notEmpty(x, "Edwards PublicKey 'x' value cannot be null or empty.");
        //TODO: assert that the curve contains the specified key
        put(ctx, DefaultOctetPublicJwk.CRV, crv.getId());
        put(ctx, DefaultOctetPublicJwk.X, x);
        return new DefaultOctetPublicJwk<>(ctx);
    }

    @Override
    protected OctetPublicJwk<PublicKey> createJwkFromValues(JwkContext<PublicKey> ctx) {
        FieldReadable reader = new RequiredFieldReader(ctx);
        EdwardsCurve curve = getCurve(reader);
        byte[] x = reader.get(DefaultOctetPublicJwk.X);
        //TODO: assert that the curve contains the specified key
        PublicKey key = curve.toPublicKey(x, ctx.getProvider());
        ctx.setKey(key);
        return new DefaultOctetPublicJwk<>(ctx);
    }
}
