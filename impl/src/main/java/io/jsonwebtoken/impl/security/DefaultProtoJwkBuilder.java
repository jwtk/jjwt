package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
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
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

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
    public RsaPublicJwkBuilder forRsaChain(X509Certificate... chain) {
        Assert.notEmpty(chain, "chain cannot be null or empty.");
        return forRsaChain(Arrays.asList(chain));
    }

    @Override
    public RsaPublicJwkBuilder forRsaChain(List<X509Certificate> chain) {
        Assert.notEmpty(chain, "X509Certificate chain cannot be empty.");
        X509Certificate cert = chain.get(0);
        PublicKey key = Assert.notNull(cert.getPublicKey(), "The first X509Certificate's PublicKey cannot be null.");
        RSAPublicKey pubKey = assertChildKey(RSAPublicKey.class, key, "first X509Certificate's");
        return setKey(pubKey).setX509CertificateChain(chain);
    }

    @Override
    public EcPublicJwkBuilder forEcChain(X509Certificate... chain) {
        Assert.notEmpty(chain, "chain cannot be null or empty.");
        return forEcChain(Arrays.asList(chain));
    }

    @Override
    public EcPublicJwkBuilder forEcChain(List<X509Certificate> chain) {
        Assert.notEmpty(chain, "X509Certificate chain cannot be empty.");
        X509Certificate cert = chain.get(0);
        PublicKey key = Assert.notNull(cert.getPublicKey(), "The first X509Certificate's PublicKey cannot be null.");
        ECPublicKey pubKey = assertChildKey(ECPublicKey.class, key, "first X509Certificate's");
        return setKey(pubKey).setX509CertificateChain(chain);
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

    private static <T extends Key> T assertChildKey(Class<T> clazz, Key key, String parentName) {
        String type = PrivateKey.class.isAssignableFrom(clazz) ? "private" : "public";
        if (key == null) {
            String msg = "The " + parentName + " " + type + " key cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (!clazz.isInstance(key)) {
            String msg = "The " + parentName + " " + type + " key must be an instance of " + clazz.getName() +
                ". Type found: " + key.getClass().getName();
            throw new IllegalArgumentException(msg);
        }
        return clazz.cast(key);
    }

    @Override
    public RsaPrivateJwkBuilder setKeyPairRsa(KeyPair keyPair) {
        Assert.notNull(keyPair, "KeyPair cannot be null.");
        RSAPublicKey pub = assertChildKey(RSAPublicKey.class, keyPair.getPublic(), "KeyPair");
        RSAPrivateKey priv = assertChildKey(RSAPrivateKey.class, keyPair.getPrivate(), "KeyPair");
        return setKey(priv).setPublicKey(pub);
    }

    @Override
    public EcPrivateJwkBuilder setKeyPairEc(KeyPair keyPair) {
        Assert.notNull(keyPair, "KeyPair cannot be null.");
        ECPublicKey pub = assertChildKey(ECPublicKey.class, keyPair.getPublic(), "KeyPair");
        ECPrivateKey priv = assertChildKey(ECPrivateKey.class, keyPair.getPrivate(), "KeyPair");
        return setKey(priv).setPublicKey(pub);
    }
}
