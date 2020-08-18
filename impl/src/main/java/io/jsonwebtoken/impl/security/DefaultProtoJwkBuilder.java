package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.EcPrivateJwkBuilder;
import io.jsonwebtoken.security.EcPublicJwkBuilder;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.ProtoJwkBuilder;
import io.jsonwebtoken.security.RsaPrivateJwkBuilder;
import io.jsonwebtoken.security.RsaPublicJwkBuilder;
import io.jsonwebtoken.security.SecretJwkBuilder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

public class DefaultProtoJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>>
    extends AbstractJwkBuilder<K, J, T> implements ProtoJwkBuilder<K, J, T> {

    public DefaultProtoJwkBuilder() {
        super(new DefaultJwkContext<K>());
    }

    @Override
    public SecretJwkBuilder setKey(SecretKey key) {
        return new AbstractJwkBuilder.DefaultSecretJwkBuilder(this.jwkContext, key);
    }

    @Override
    public RsaPublicJwkBuilder setKey(RSAPublicKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultRsaPublicJwkBuilder(this.jwkContext, key);
    }

    @Override
    public RsaPrivateJwkBuilder setKey(RSAPrivateKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultRsaPrivateJwkBuilder(this.jwkContext, key);
    }

    @Override
    public EcPublicJwkBuilder setKey(ECPublicKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultEcPublicJwkBuilder(this.jwkContext, key);
    }

    @Override
    public EcPrivateJwkBuilder setKey(ECPrivateKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultEcPrivateJwkBuilder(this.jwkContext, key);
    }

    private static <T extends Key> T assertKeyPairChild(Class<T> clazz, Key key) {
        String type = PrivateKey.class.isAssignableFrom(clazz) ? "private" : "public";
        if (key == null) {
            String msg = "KeyPair " + type + " key cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (!clazz.isInstance(key)) {
            String msg = "The specified KeyPair's " + type + " key must be an instance of " + clazz.getName() +
                ". Type found: " + key.getClass().getName();
            throw new IllegalArgumentException(msg);
        }
        return clazz.cast(key);
    }

    @Override
    public RsaPrivateJwkBuilder setKeyPairRsa(KeyPair keyPair) {
        Assert.notNull(keyPair, "KeyPair cannot be null.");
        RSAPublicKey pub = assertKeyPairChild(RSAPublicKey.class, keyPair.getPublic());
        RSAPrivateKey priv = assertKeyPairChild(RSAPrivateKey.class, keyPair.getPrivate());
        return setKey(priv).setPublicKey(pub);
    }

    @Override
    public EcPrivateJwkBuilder setKeyPairEc(KeyPair keyPair) {
        Assert.notNull(keyPair, "KeyPair cannot be null.");
        ECPublicKey pub = assertKeyPairChild(ECPublicKey.class, keyPair.getPublic());
        ECPrivateKey priv = assertKeyPairChild(ECPrivateKey.class, keyPair.getPrivate());
        return setKey(priv).setPublicKey(pub);
    }
}
