/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.EcPrivateJwkBuilder;
import io.jsonwebtoken.security.EcPublicJwkBuilder;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.OctetPrivateJwkBuilder;
import io.jsonwebtoken.security.OctetPublicJwkBuilder;
import io.jsonwebtoken.security.PrivateJwkBuilder;
import io.jsonwebtoken.security.ProtoJwkBuilder;
import io.jsonwebtoken.security.PublicJwkBuilder;
import io.jsonwebtoken.security.RsaPrivateJwkBuilder;
import io.jsonwebtoken.security.RsaPublicJwkBuilder;
import io.jsonwebtoken.security.SecretJwkBuilder;
import io.jsonwebtoken.security.UnsupportedKeyException;

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

@SuppressWarnings("unused") //used via reflection by io.jsonwebtoken.security.Jwks
public class DefaultProtoJwkBuilder<K extends Key, J extends Jwk<K>>
        extends AbstractJwkBuilder<K, J, ProtoJwkBuilder<K, J>> implements ProtoJwkBuilder<K, J> {

    public DefaultProtoJwkBuilder() {
        super(new DefaultJwkContext<K>());
    }

    @Override
    public SecretJwkBuilder forKey(SecretKey key) {
        return new AbstractJwkBuilder.DefaultSecretJwkBuilder(newContext(key));
    }

    @Override
    public RsaPublicJwkBuilder forKey(RSAPublicKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultRsaPublicJwkBuilder(newContext(key));
    }

    @Override
    public RsaPrivateJwkBuilder forKey(RSAPrivateKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultRsaPrivateJwkBuilder(newContext(key));
    }

    @Override
    public EcPublicJwkBuilder forKey(ECPublicKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultEcPublicJwkBuilder(newContext(key));
    }

    @Override
    public EcPrivateJwkBuilder forKey(ECPrivateKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultEcPrivateJwkBuilder(newContext(key));
    }

    private static UnsupportedKeyException unsupportedKey(Key key, Exception e) {
        String msg = "There is no builder that supports specified key of type " +
                key.getClass().getName() + " with algorithm '" + key.getAlgorithm() + "'.";
        return new UnsupportedKeyException(msg, e);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <A extends PublicKey, B extends PrivateKey> PublicJwkBuilder<A, B, ?, ?, ?, ?> forKey(A key) {
        if (key instanceof RSAPublicKey) {
            return (PublicJwkBuilder<A, B, ?, ?, ?, ?>) forKey((RSAPublicKey) key);
        } else if (key instanceof ECPublicKey) {
            return (PublicJwkBuilder<A, B, ?, ?, ?, ?>) forKey((ECPublicKey) key);
        } else {
            try {
                return forOctetKey(key);
            } catch (Exception e) {
                throw unsupportedKey(key, e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public <A extends PublicKey, B extends PrivateKey> PrivateJwkBuilder<B, A, ?, ?, ?> forKey(B key) {
        Assert.notNull(key, "Key cannot be null.");
        if (key instanceof RSAPrivateKey) {
            return (PrivateJwkBuilder<B, A, ?, ?, ?>) forKey((RSAPrivateKey) key);
        } else if (key instanceof ECPrivateKey) {
            return (PrivateJwkBuilder<B, A, ?, ?, ?>) forKey((ECPrivateKey) key);
        } else {
            try {
                return forOctetKey(key);
            } catch (Exception e) {
                throw unsupportedKey(key, e);
            }
        }
    }

    @Override
    public <A extends PublicKey, B extends PrivateKey> OctetPublicJwkBuilder<A, B> forOctetKey(A key) {
        return new AbstractAsymmetricJwkBuilder.DefaultOctetPublicJwkBuilder<>(newContext(key));
    }

    @Override
    public <A extends PrivateKey, B extends PublicKey> OctetPrivateJwkBuilder<A, B> forOctetKey(A key) {
        return new AbstractAsymmetricJwkBuilder.DefaultOctetPrivateJwkBuilder<>(newContext(key));
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
        PublicKey key = cert.getPublicKey();
        RSAPublicKey pubKey = KeyPairs.assertKey(key, RSAPublicKey.class, "The first X509Certificate's ");
        return forKey(pubKey).setX509CertificateChain(chain);
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
        PublicKey key = cert.getPublicKey();
        ECPublicKey pubKey = KeyPairs.assertKey(key, ECPublicKey.class, "The first X509Certificate's ");
        return forKey(pubKey).setX509CertificateChain(chain);
    }

    @SuppressWarnings("unchecked") // ok because of the EdwardsCurve.assertEdwards calls
    @Override
    public <A extends PrivateKey, B extends PublicKey> OctetPrivateJwkBuilder<A, B> forOctetKeyPair(KeyPair pair) {
        PublicKey pub = KeyPairs.getKey(pair, PublicKey.class);
        PrivateKey priv = KeyPairs.getKey(pair, PrivateKey.class);
        EdwardsCurve.assertEdwards(pub);
        EdwardsCurve.assertEdwards(priv);
        return (OctetPrivateJwkBuilder<A, B>) forOctetKey(priv).setPublicKey(pub);
    }

    @Override
    public <A extends PublicKey, B extends PrivateKey> OctetPublicJwkBuilder<A, B> forOctetChain(X509Certificate... chain) {
        Assert.notEmpty(chain, "X509Certificate chain cannot be null or empty.");
        return forOctetChain(Arrays.asList(chain));
    }

    @SuppressWarnings("unchecked") // ok because of the EdwardsCurve.assertEdwards calls
    @Override
    public <A extends PublicKey, B extends PrivateKey> OctetPublicJwkBuilder<A, B> forOctetChain(List<X509Certificate> chain) {
        Assert.notEmpty(chain, "X509Certificate chain cannot be empty.");
        X509Certificate cert = chain.get(0);
        PublicKey key = cert.getPublicKey();
        Assert.notNull(key, "The first X509Certificate's PublicKey cannot be null.");
        EdwardsCurve.assertEdwards(key);
        return this.<A, B>forOctetKey((A) key).setX509CertificateChain(chain);
    }

    @Override
    public RsaPrivateJwkBuilder forRsaKeyPair(KeyPair pair) {
        RSAPublicKey pub = KeyPairs.getKey(pair, RSAPublicKey.class);
        RSAPrivateKey priv = KeyPairs.getKey(pair, RSAPrivateKey.class);
        return forKey(priv).setPublicKey(pub);
    }

    @Override
    public EcPrivateJwkBuilder forEcKeyPair(KeyPair pair) {
        ECPublicKey pub = KeyPairs.getKey(pair, ECPublicKey.class);
        ECPrivateKey priv = KeyPairs.getKey(pair, ECPrivateKey.class);
        return forKey(priv).setPublicKey(pub);
    }

    @Override
    public J build() {
        if (Strings.hasText(this.DELEGATE.get(AbstractJwk.KTY))) {
            // Ensure we have a context that represents the configured kty value.  Converting the existing context to
            // the type-specific context will also perform any necessary field value type conversion / error checking
            // this will also perform any necessary field value type conversions / error checking
            setDelegate(this.jwkFactory.newContext(this.DELEGATE, this.DELEGATE.getKey()));
        }
        return super.build();
    }
}
