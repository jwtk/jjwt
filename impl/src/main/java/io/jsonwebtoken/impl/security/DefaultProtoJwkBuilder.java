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
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@SuppressWarnings("unused") //used via reflection by io.jsonwebtoken.security.Jwks
public class DefaultProtoJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>>
    extends AbstractJwkBuilder<K, J, T> implements ProtoJwkBuilder<K, J, T> {

    public DefaultProtoJwkBuilder() {
        super(new DefaultJwkContext<K>());
    }

    @Override
    public SecretJwkBuilder forKey(SecretKey key) {
        return new AbstractJwkBuilder.DefaultSecretJwkBuilder(this.jwkContext, key);
    }

    @Override
    public RsaPublicJwkBuilder forKey(RSAPublicKey key) {
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

    @Override
    public RsaPrivateJwkBuilder forKey(RSAPrivateKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultRsaPrivateJwkBuilder(this.jwkContext, key);
    }

    @Override
    public EcPublicJwkBuilder forKey(ECPublicKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultEcPublicJwkBuilder(this.jwkContext, key);
    }

    @Override
    public EcPrivateJwkBuilder forKey(ECPrivateKey key) {
        return new AbstractAsymmetricJwkBuilder.DefaultEcPrivateJwkBuilder(this.jwkContext, key);
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
}
