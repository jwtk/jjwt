package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;

import java.security.Key;

class AsymmetricJwkFactory implements FamilyJwkFactory<Key, Jwk<Key>> {

    private final String id;
    private final FamilyJwkFactory<Key, Jwk<Key>> publicFactory;
    private final FamilyJwkFactory<Key, Jwk<Key>> privateFactory;

    @SuppressWarnings({"unchecked", "rawtypes"})
    AsymmetricJwkFactory(FamilyJwkFactory publicFactory, FamilyJwkFactory privateFactory) {
        this.publicFactory = (FamilyJwkFactory<Key, Jwk<Key>>) Assert.notNull(publicFactory, "publicFactory cannot be null.");
        this.privateFactory = (FamilyJwkFactory<Key, Jwk<Key>>) Assert.notNull(privateFactory, "privateFactory cannot be null.");
        this.id = Assert.notNull(publicFactory.getId(), "publicFactory id cannot be null or empty.");
        Assert.isTrue(this.id.equals(privateFactory.getId()), "privateFactory id must equal publicFactory id");
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public boolean supports(JwkContext<?> ctx) {
        return this.id.equals(ctx.getType()) || privateFactory.supports(ctx) || publicFactory.supports(ctx);
    }

    @Override
    public Jwk<Key> createJwk(JwkContext<Key> ctx) {
        if (privateFactory.supports(ctx)) {
            return this.privateFactory.createJwk(ctx);
        }
        return this.publicFactory.createJwk(ctx);
    }
}
