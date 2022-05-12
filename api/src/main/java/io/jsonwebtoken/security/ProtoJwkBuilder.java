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
package io.jsonwebtoken.security;

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

/**
 * A prototypical {@link JwkBuilder} that coerces to a more type-specific builder based on the {@link Key} that will
 * be represented as a JWK.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtoJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>> extends JwkBuilder<K, J, T> {

    /**
     * Ensures the builder will create a {@link SecretJwk} for the specified Java {@link SecretKey}.
     *
     * @param key the {@link SecretKey} to represent as a {@link SecretJwk}.
     * @return the builder coerced as a {@link SecretJwkBuilder}.
     */
    SecretJwkBuilder setKey(SecretKey key);

    /**
     * Ensures the builder will create an {@link RsaPublicJwk} for the specified Java {@link RSAPublicKey}.
     *
     * @param key the {@link RSAPublicKey} to represent as a {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPublicJwkBuilder}.
     */
    RsaPublicJwkBuilder setKey(RSAPublicKey key);

    /**
     * Ensures the builder will create an {@link RsaPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at array index 0) <em>MUST</em> contain an {@link RSAPublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link RSAPublicKey} to represent as a
     *              {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPublicJwkBuilder}.
     */
    RsaPublicJwkBuilder forRsaChain(X509Certificate... chain);

    /**
     * Ensures the builder will create an {@link RsaPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at list index 0) <em>MUST</em> contain an {@link RSAPublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link RSAPublicKey} to represent as a
     *              {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPublicJwkBuilder}.
     */
    RsaPublicJwkBuilder forRsaChain(List<X509Certificate> chain);

    /**
     * Ensures the builder will create an {@link RsaPrivateJwk} for the specified Java {@link RSAPrivateKey}. If
     * possible, it is recommended to also call the resulting builder's
     * {@link RsaPrivateJwkBuilder#setPublicKey(PublicKey) setPublicKey} method with the private key's matching
     * {@link PublicKey} for better performance.  See the
     * {@link RsaPrivateJwkBuilder#setPublicKey(PublicKey) setPublicKey} and {@link PrivateJwk} JavaDoc for more
     * information.
     *
     * @param key the {@link RSAPublicKey} to represent as a {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPrivateJwkBuilder}.
     */
    RsaPrivateJwkBuilder setKey(RSAPrivateKey key);

    /**
     * Ensures the builder will create an {@link EcPublicJwk} for the specified Java {@link ECPublicKey}.
     *
     * @param key the {@link ECPublicKey} to represent as a {@link EcPublicJwk}.
     * @return the builder coerced as an {@link EcPublicJwkBuilder}.
     */
    EcPublicJwkBuilder setKey(ECPublicKey key);

    /**
     * Ensures the builder will create an {@link EcPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at array index 0) <em>MUST</em> contain an {@link ECPublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link ECPublicKey} to represent as a
     *              {@link EcPublicJwk}.
     * @return the builder coerced as an {@link EcPublicJwkBuilder}.
     */
    EcPublicJwkBuilder forEcChain(X509Certificate... chain);

    /**
     * Ensures the builder will create an {@link EcPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at list index 0) <em>MUST</em> contain an {@link ECPublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link ECPublicKey} to represent as a
     *              {@link EcPublicJwk}.
     * @return the builder coerced as an {@link EcPublicJwkBuilder}.
     */
    EcPublicJwkBuilder forEcChain(List<X509Certificate> chain);

    /**
     * Ensures the builder will create an {@link EcPrivateJwk} for the specified Java {@link ECPrivateKey}. If
     * possible, it is recommended to also call the resulting builder's
     * {@link EcPrivateJwkBuilder#setPublicKey(PublicKey) setPublicKey} method with the private key's matching
     * {@link PublicKey} for better performance.  See the
     * {@link EcPrivateJwkBuilder#setPublicKey(PublicKey) setPublicKey} and {@link PrivateJwk} JavaDoc for more
     * information.
     *
     * @param key the {@link ECPublicKey} to represent as an {@link EcPublicJwk}.
     * @return the builder coerced as a {@link EcPrivateJwkBuilder}.
     */
    EcPrivateJwkBuilder setKey(ECPrivateKey key);

    /**
     * Ensures the builder will create an {@link RsaPrivateJwk} for the specified Java RSA
     * {@link KeyPair}.  The pair's {@link KeyPair#getPublic() public key} <em>MUST</em> be an
     * {@link RSAPublicKey} instance.  The pair's {@link KeyPair#getPrivate() private key} <em>MUST</em> be an
     * {@link RSAPrivateKey} instance.
     *
     * @param keyPair the RSA {@link KeyPair} to represent as an {@link RsaPrivateJwk}.
     * @return the builder coerced as an {@link RsaPrivateJwkBuilder}.
     * @throws IllegalArgumentException if the {@code keyPair} does not contain {@link RSAPublicKey} and
     *                                  {@link RSAPrivateKey} instances.
     */
    RsaPrivateJwkBuilder setKeyPairRsa(KeyPair keyPair) throws IllegalArgumentException;

    /**
     * Ensures the builder will create an {@link EcPrivateJwk} for the specified Java Elliptic Curve
     * {@link KeyPair}.  The pair's {@link KeyPair#getPublic() public key} <em>MUST</em> be an
     * {@link ECPublicKey} instance.  The pair's {@link KeyPair#getPrivate() private key} <em>MUST</em> be an
     * {@link ECPrivateKey} instance.
     *
     * @param keyPair the EC {@link KeyPair} to represent as an {@link EcPrivateJwk}.
     * @return the builder coerced as an {@link EcPrivateJwkBuilder}.
     * @throws IllegalArgumentException if the {@code keyPair} does not contain {@link ECPublicKey} and
     *                                  {@link ECPrivateKey} instances.
     */
    EcPrivateJwkBuilder setKeyPairEc(KeyPair keyPair) throws IllegalArgumentException;
}
