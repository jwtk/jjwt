package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.RequiredFieldReader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PrivateKey;
import java.security.PublicKey;

public class OctetPrivateJwkFactory extends OctetJwkFactory<PrivateKey, PrivateJwk<PrivateKey, PublicKey, PublicJwk<PublicKey>>> {

    public OctetPrivateJwkFactory() {
        super(PrivateKey.class, DefaultOctetPrivateJwk.FIELDS);
    }

    @Override
    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return super.supportsKeyValues(ctx) && ctx.containsKey(DefaultOctetPrivateJwk.D.getId());
    }

    @Override
    protected PrivateJwk<PrivateKey, PublicKey, PublicJwk<PublicKey>> createJwkFromKey(JwkContext<PrivateKey> ctx) {
        PrivateKey key = Assert.notNull(ctx.getKey(), "PrivateKey cannot be null.");
        EdwardsCurve crv = EdwardsCurve.forKey(key);

        PublicKey pub = ctx.getPublicKey();
        Assert.notNull(pub, "Private OKP instances require the PublicKey to be provided.");
        if (!crv.equals(EdwardsCurve.forKey(pub))) {
            String msg = "Specified Edwards Curve PublicKey does not match the PrivateKey curve.";
            throw new InvalidKeyException(msg);
        }

        // If a JWK fingerprint has been requested to be the JWK id, ensure we copy over the one computed for the
        // public key per https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        boolean copyId = !Strings.hasText(ctx.getId()) && ctx.getIdThumbprintAlgorithm() != null;
        JwkContext<PublicKey> pubCtx = OctetPublicJwkFactory.INSTANCE.newContext(ctx, pub);
        PublicJwk<PublicKey> pubJwk = OctetPublicJwkFactory.INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk);
        if (copyId) {
            ctx.setId(pubJwk.getId());
        }

        //now add the d value
        byte[] d = crv.getKeyMaterial(key);
        Assert.notEmpty(d, "Edwards PrivateKey 'd' value cannot be null or empty.");
        //TODO: assert that the curve contains the specified key
        put(ctx, DefaultOctetPrivateJwk.D, d);

        return new DefaultOctetPrivateJwk<>(ctx, pubJwk);
    }

    @Override
    protected PrivateJwk<PrivateKey, PublicKey, PublicJwk<PublicKey>> createJwkFromValues(JwkContext<PrivateKey> ctx) {
        FieldReadable reader = new RequiredFieldReader(ctx);
        EdwardsCurve curve = getCurve(reader);
        //TODO: assert that the curve contains the specified key

        // public values are required, so assert them:
        JwkContext<PublicKey> pubCtx = new DefaultJwkContext<>(DefaultOctetPublicJwk.FIELDS, ctx);
        PublicJwk<PublicKey> pubJwk = OctetPublicJwkFactory.INSTANCE.createJwkFromValues(pubCtx);

        byte[] d = reader.get(DefaultOctetPrivateJwk.D);
        PrivateKey key = curve.toPrivateKey(d, ctx.getProvider());
        ctx.setKey(key);

        return new DefaultOctetPrivateJwk<>(ctx, pubJwk);
    }
}
