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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * A {@link JwkBuilder} that coerces to a more type-specific builder based on the {@link Key} that will be
 * represented as a JWK.
 *
 * @param <K> the type of Java {@link Key} represented by the created {@link Jwk}.
 * @param <J> the type of {@link Jwk} created by the builder
 * @since JJWT_RELEASE_VERSION
 */
public interface DynamicJwkBuilder<K extends Key, J extends Jwk<K>> extends JwkBuilder<K, J, DynamicJwkBuilder<K, J>> {

    /**
     * Ensures the builder will create a {@link PublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at array index 0) <em>MUST</em> contain a {@link PublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * <p>This method is provided for congruence with the other {@code chain} methods and is expected to be used when
     * the calling code has a variable {@code PublicKey} reference. Based on the argument type, it will
     * delegate to one of the following methods if possible:
     * <ul>
     *     <li>{@link #rsaChain(List)}</li>
     *     <li>{@link #ecChain(List)}</li>
     *     <li>{@link #octetChain(List)}</li>
     * </ul>
     *
     * <p>If the specified {@code chain} argument is not capable of being supported by one of those methods, an
     * {@link UnsupportedKeyException} will be thrown.</p>
     *
     * <p><b>Type Parameters</b></p>
     *
     * <p>In addition to the public key type <code>A</code>, the public key's associated private key type
     * <code>B</code> is parameterized as well. This ensures that any subsequent call to the builder's
     * {@link PublicJwkBuilder#privateKey(PrivateKey) privateKey} method will be type-safe.  For example:</p>
     *
     * <blockquote><pre>Jwks.builder().&lt;EdECPublicKey, <b>EdECPrivateKey</b>&gt;chain(edECPublicKeyX509CertificateChain)
     *     .privateKey(<b>aPrivateKey</b>) // &lt;-- must be an EdECPrivateKey instance
     *     ... etc ...
     *     .build();</pre></blockquote>
     *
     * @param <A>   the type of {@link PublicKey} provided by the created public JWK.
     * @param <B>   the type of {@link PrivateKey} that may be paired with the {@link PublicKey} to produce a
     *              {@link PrivateJwk} if desired.
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link PublicKey} to represent as a
     *              {@link PublicJwk}.
     * @return the builder coerced as a {@link PublicJwkBuilder} for continued method chaining.
     * @throws UnsupportedKeyException if the specified key is not a supported type and cannot be used to delegate to
     *                                 other {@code key} methods.
     * @see PublicJwk
     * @see PrivateJwk
     */
    <A extends PublicKey, B extends PrivateKey> PublicJwkBuilder<A, B, ?, ?, ?, ?> chain(List<X509Certificate> chain)
            throws UnsupportedKeyException;

    /**
     * Ensures the builder will create a {@link SecretJwk} for the specified Java {@link SecretKey}.
     *
     * @param key the {@link SecretKey} to represent as a {@link SecretJwk}.
     * @return the builder coerced as a {@link SecretJwkBuilder}.
     */
    SecretJwkBuilder key(SecretKey key);

    /**
     * Ensures the builder will create an {@link RsaPublicJwk} for the specified Java {@link RSAPublicKey}.
     *
     * @param key the {@link RSAPublicKey} to represent as a {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPublicJwkBuilder}.
     */
    RsaPublicJwkBuilder key(RSAPublicKey key);

    /**
     * Ensures the builder will create an {@link RsaPrivateJwk} for the specified Java {@link RSAPrivateKey}. If
     * possible, it is recommended to also call the resulting builder's
     * {@link RsaPrivateJwkBuilder#publicKey(PublicKey) publicKey} method with the private key's matching
     * {@link PublicKey} for better performance.  See the
     * {@link RsaPrivateJwkBuilder#publicKey(PublicKey) publicKey} and {@link PrivateJwk} JavaDoc for more
     * information.
     *
     * @param key the {@link RSAPublicKey} to represent as a {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPrivateJwkBuilder}.
     */
    RsaPrivateJwkBuilder key(RSAPrivateKey key);

    /**
     * Ensures the builder will create an {@link EcPublicJwk} for the specified Java {@link ECPublicKey}.
     *
     * @param key the {@link ECPublicKey} to represent as a {@link EcPublicJwk}.
     * @return the builder coerced as an {@link EcPublicJwkBuilder}.
     */
    EcPublicJwkBuilder key(ECPublicKey key);

    /**
     * Ensures the builder will create an {@link EcPrivateJwk} for the specified Java {@link ECPrivateKey}. If
     * possible, it is recommended to also call the resulting builder's
     * {@link EcPrivateJwkBuilder#publicKey(PublicKey) publicKey} method with the private key's matching
     * {@link PublicKey} for better performance.  See the
     * {@link EcPrivateJwkBuilder#publicKey(PublicKey) publicKey} and {@link PrivateJwk} JavaDoc for more
     * information.
     *
     * @param key the {@link ECPublicKey} to represent as an {@link EcPublicJwk}.
     * @return the builder coerced as a {@link EcPrivateJwkBuilder}.
     */
    EcPrivateJwkBuilder key(ECPrivateKey key);

    /**
     * Ensures the builder will create a {@link PublicJwk} for the specified Java {@link PublicKey} argument. This
     * method is provided for congruence with the other {@code key} methods and is expected to be used when
     * the calling code has an untyped {@code PublicKey} reference. Based on the argument type, it will delegate to one
     * of the following methods if possible:
     * <ul>
     *     <li>{@link #key(RSAPublicKey)}</li>
     *     <li>{@link #key(ECPublicKey)}</li>
     *     <li>{@link #octetKey(PublicKey)}</li>
     * </ul>
     *
     * <p>If the specified {@code key} argument is not capable of being supported by one of those methods, an
     * {@link UnsupportedKeyException} will be thrown.</p>
     *
     * <p><b>Type Parameters</b></p>
     *
     * <p>In addition to the public key type <code>A</code>, the public key's associated private key type
     * <code>B</code> is parameterized as well. This ensures that any subsequent call to the builder's
     * {@link PublicJwkBuilder#privateKey(PrivateKey) privateKey} method will be type-safe.  For example:</p>
     *
     * <blockquote><pre>Jwks.builder().&lt;EdECPublicKey, <b>EdECPrivateKey</b>&gt;key(anEdECPublicKey)
     *     .privateKey(<b>aPrivateKey</b>) // &lt;-- must be an EdECPrivateKey instance
     *     ... etc ...
     *     .build();</pre></blockquote>
     *
     * @param <A> the type of {@link PublicKey} provided by the created public JWK.
     * @param <B> the type of {@link PrivateKey} that may be paired with the {@link PublicKey} to produce a
     *            {@link PrivateJwk} if desired.
     * @param key the {@link PublicKey} to represent as a {@link PublicJwk}.
     * @return the builder coerced as a {@link PublicJwkBuilder} for continued method chaining.
     * @throws UnsupportedKeyException if the specified key is not a supported type and cannot be used to delegate to
     *                                 other {@code key} methods.
     * @see PublicJwk
     * @see PrivateJwk
     */
    <A extends PublicKey, B extends PrivateKey> PublicJwkBuilder<A, B, ?, ?, ?, ?> key(A key) throws UnsupportedKeyException;

    /**
     * Ensures the builder will create a {@link PrivateJwk} for the specified Java {@link PrivateKey} argument. This
     * method is provided for congruence with the other {@code key} methods and is expected to be used when
     * the calling code has an untyped {@code PrivateKey} reference. Based on the argument type, it will delegate to one
     * of the following methods if possible:
     * <ul>
     *     <li>{@link #key(RSAPrivateKey)}</li>
     *     <li>{@link #key(ECPrivateKey)}</li>
     *     <li>{@link #octetKey(PrivateKey)}</li>
     * </ul>
     *
     * <p>If the specified {@code key} argument is not capable of being supported by one of those methods, an
     * {@link UnsupportedKeyException} will be thrown.</p>
     *
     * <p><b>Type Parameters</b></p>
     *
     * <p>In addition to the private key type <code>B</code>, the private key's associated public key type
     * <code>A</code> is parameterized as well. This ensures that any subsequent call to the builder's
     * {@link PrivateJwkBuilder#publicKey(PublicKey) publicKey} method will be type-safe.  For example:</p>
     *
     * <blockquote><pre>Jwks.builder().&lt;<b>EdECPublicKey</b>, EdECPrivateKey&gt;key(anEdECPrivateKey)
     *     .publicKey(<b>aPublicKey</b>) // &lt;-- must be an EdECPublicKey instance
     *     ... etc ...
     *     .build();</pre></blockquote>
     *
     * @param <A> the type of {@link PublicKey} paired with the {@code key} argument to produce the {@link PrivateJwk}.
     * @param <B> the type of the {@link PrivateKey} argument.
     * @param key the {@link PrivateKey} to represent as a {@link PrivateJwk}.
     * @return the builder coerced as a {@link PrivateJwkBuilder} for continued method chaining.
     * @throws UnsupportedKeyException if the specified key is not a supported type and cannot be used to delegate to
     *                                 other {@code key} methods.
     * @see PublicJwk
     * @see PrivateJwk
     */
    <A extends PublicKey, B extends PrivateKey> PrivateJwkBuilder<B, A, ?, ?, ?> key(B key) throws UnsupportedKeyException;

    /**
     * Ensures the builder will create a {@link PrivateJwk} for the specified Java {@link KeyPair} argument. This
     * method is provided for congruence with the other {@code keyPair} methods and is expected to be used when
     * the calling code has a variable {@code PrivateKey} reference. Based on the argument's {@code PrivateKey} type,
     * it will delegate to one of the following methods if possible:
     * <ul>
     *     <li>{@link #key(RSAPrivateKey)}</li>
     *     <li>{@link #key(ECPrivateKey)}</li>
     *     <li>{@link #octetKey(PrivateKey)}</li>
     * </ul>
     * <p>and automatically set the resulting builder's {@link PrivateJwkBuilder#publicKey(PublicKey) publicKey} with
     * the pair's {@code PublicKey}.</p>
     *
     * <p>If the specified {@code key} argument is not capable of being supported by one of those methods, an
     * {@link UnsupportedKeyException} will be thrown.</p>
     *
     * <p><b>Type Parameters</b></p>
     *
     * <p>In addition to the private key type <code>B</code>, the private key's associated public key type
     * <code>A</code> is parameterized as well. This ensures that any subsequent call to the builder's
     * {@link PrivateJwkBuilder#publicKey(PublicKey) publicKey} method will be type-safe.  For example:</p>
     *
     * <blockquote><pre>Jwks.builder().&lt;<b>EdECPublicKey</b>, EdECPrivateKey&gt;keyPair(anEdECKeyPair)
     *     .publicKey(<b>aPublicKey</b>) // &lt;-- must be an EdECPublicKey instance
     *     ... etc ...
     *     .build();</pre></blockquote>
     *
     * @param <A>     the {@code keyPair} argument's {@link PublicKey} type
     * @param <B>     the {@code keyPair} argument's {@link PrivateKey} type
     * @param keyPair the {@code KeyPair} containing the public and private key
     * @return the builder coerced as a {@link PrivateJwkBuilder} for continued method chaining.
     * @throws UnsupportedKeyException if the specified {@code KeyPair}'s keys are not supported and cannot be used to
     *                                 delegate to other {@code key} methods.
     * @see PublicJwk
     * @see PrivateJwk
     */
    <A extends PublicKey, B extends PrivateKey> PrivateJwkBuilder<B, A, ?, ?, ?> keyPair(KeyPair keyPair)
            throws UnsupportedKeyException;

    /**
     * Ensures the builder will create an {@link OctetPublicJwk} for the specified Edwards-curve {@code PublicKey}
     * argument.  The {@code PublicKey} must be an instance of one of the following:
     * <ul>
     *     <li><a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/interfaces/XECPublicKey.html">java.security.interfaces.XECPublicKey</a>, introduced in JDK 11</li>
     *     <li><a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECPublicKey.html">java.security.interfaces.EdECPublicKey</a>, introduced in JDK 15</li>
     *     <li>A {@code PublicKey} with a valid Edwards Curve DER {@link Key#getEncoded() encoding}, such as those
     *         provided by BouncyCastle on earlier JDKs.</li>
     * </ul>
     *
     * <p><b>Type Parameters</b></p>
     *
     * <p>In addition to the public key type <code>A</code>, the public key's associated private key type
     * <code>B</code> is parameterized as well. This ensures that any subsequent call to the builder's
     * {@link PublicJwkBuilder#privateKey(PrivateKey) privateKey} method will be type-safe.  For example:</p>
     *
     * <blockquote><pre>Jwks.builder().&lt;EdECPublicKey, <b>EdECPrivateKey</b>&gt;key(anEdECPublicKey)
     *     .privateKey(<b>aPrivateKey</b>) // &lt;-- must be an EdECPrivateKey instance
     *     ... etc ...
     *     .build();</pre></blockquote>
     *
     * @param <A> the type of Edwards-curve {@link PublicKey} provided by the created public JWK.
     * @param <B> the type of Edwards-curve {@link PrivateKey} that may be paired with the {@link PublicKey} to produce
     *            an {@link OctetPrivateJwk} if desired.
     * @param key the Edwards-curve {@link PublicKey} to represent as an {@link OctetPublicJwk}.
     * @return the builder coerced as a {@link OctetPublicJwkBuilder} for continued method chaining.
     * @throws UnsupportedKeyException if the specified key is not a supported Edwards-curve key.
     * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/interfaces/XECPublicKey.html">java.security.interfaces.XECPublicKey</a>
     * @see <a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECPublicKey.html">java.security.interfaces.EdECPublicKey</a>
     */
    <A extends PublicKey, B extends PrivateKey> OctetPublicJwkBuilder<A, B> octetKey(A key);

    /**
     * Ensures the builder will create an {@link OctetPrivateJwk} for the specified Edwards-curve {@code PrivateKey}
     * argument.  The {@code PrivateKey} must be an instance of one of the following:
     * <ul>
     *     <li><a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/interfaces/XECPrivateKey.html">
     *         java.security.interfaces.XECPrivateKey</a>, introduced in JDK 11</li>
     *     <li><a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECPrivateKey.html">
     *         java.security.interfaces.EdECPrivateKey</a>, introduced in JDK 15</li>
     *     <li>A {@code PrivateKey} with a valid Edwards Curve DER {@link Key#getEncoded() encoding}, such as those
     *         provided by BouncyCastle on earlier JDKs.</li>
     * </ul>
     *
     * <p><b>Type Parameters</b></p>
     *
     * <p>In addition to the private key type <code>B</code>, the private key's associated public key type
     * <code>A</code> is parameterized as well. This ensures that any subsequent call to the builder's
     * {@link PrivateJwkBuilder#publicKey(PublicKey) publicKey} method will be type-safe.  For example:</p>
     *
     * <blockquote><pre>Jwks.builder().&lt;<b>EdECPublicKey</b>, EdECPrivateKey&gt;key(anEdECPrivateKey)
     *     .publicKey(<b>aPublicKey</b>) // &lt;-- must be an EdECPublicKey instance
     *     ... etc ...
     *     .build();</pre></blockquote>
     *
     * @param <A> the type of the Edwards-curve {@link PrivateKey} argument.
     * @param <B> the type of Edwards-curve {@link PublicKey} paired with the {@code key} argument to produce the
     *            {@link OctetPrivateJwk}.
     * @param key the Edwards-curve {@link PrivateKey} to represent as an {@link OctetPrivateJwk}.
     * @return the builder coerced as an {@link OctetPrivateJwkBuilder} for continued method chaining.
     * @throws UnsupportedKeyException if the specified key is not a supported Edwards-curve key.
     * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/interfaces/XECPrivateKey.html">java.security.interfaces.XECPrivateKey</a>
     * @see <a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECPrivateKey.html">java.security.interfaces.EdECPrivateKey</a>
     */
    <A extends PrivateKey, B extends PublicKey> OctetPrivateJwkBuilder<A, B> octetKey(A key);

    /**
     * Ensures the builder will create an {@link OctetPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at list index 0) <em>MUST</em>
     * {@link X509Certificate#getPublicKey() contain} an Edwards-curve public key as defined by
     * {@link #octetKey(PublicKey)}.
     *
     * @param <A>   the type of Edwards-curve {@link PublicKey} contained in the first {@code X509Certificate}.
     * @param <B>   the type of Edwards-curve {@link PrivateKey} that may be paired with the {@link PublicKey} to produce
     *              an {@link OctetPrivateJwk} if desired.
     * @param chain the {@link X509Certificate} chain to inspect to find the Edwards-curve {@code PublicKey} to
     *              represent as an {@link OctetPublicJwk}.
     * @return the builder coerced as an {@link OctetPublicJwkBuilder} for continued method chaining.
     */
    <A extends PublicKey, B extends PrivateKey> OctetPublicJwkBuilder<A, B> octetChain(List<X509Certificate> chain);

    /**
     * Ensures the builder will create an {@link OctetPrivateJwk} for the specified Java Edwards-curve
     * {@link KeyPair}.  The pair's {@link KeyPair#getPublic() public key} <em>MUST</em> be an
     * Edwards-curve public key as defined by {@link #octetKey(PublicKey)}.  The pair's
     * {@link KeyPair#getPrivate() private key} <em>MUST</em> be an Edwards-curve private key as defined by
     * {@link #octetKey(PrivateKey)}.
     *
     * @param <A>     the type of Edwards-curve {@link PublicKey} contained in the key pair.
     * @param <B>     the type of the Edwards-curve {@link PrivateKey} contained in the key pair.
     * @param keyPair the Edwards-curve {@link KeyPair} to represent as an {@link OctetPrivateJwk}.
     * @return the builder coerced as an {@link OctetPrivateJwkBuilder} for continued method chaining.
     * @throws IllegalArgumentException if the {@code keyPair} does not contain Edwards-curve public and private key
     *                                  instances.
     */
    <A extends PrivateKey, B extends PublicKey> OctetPrivateJwkBuilder<A, B> octetKeyPair(KeyPair keyPair);

    /**
     * Ensures the builder will create an {@link EcPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at list index 0) <em>MUST</em> contain an {@link ECPublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link ECPublicKey} to represent as a
     *              {@link EcPublicJwk}.
     * @return the builder coerced as an {@link EcPublicJwkBuilder}.
     */
    EcPublicJwkBuilder ecChain(List<X509Certificate> chain);

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
    EcPrivateJwkBuilder ecKeyPair(KeyPair keyPair) throws IllegalArgumentException;

    /**
     * Ensures the builder will create an {@link RsaPublicJwk} for the specified Java {@link X509Certificate} chain.
     * The first {@code X509Certificate} in the chain (at list index 0) <em>MUST</em> contain an {@link RSAPublicKey}
     * instance when calling the certificate's {@link X509Certificate#getPublicKey() getPublicKey()} method.
     *
     * @param chain the {@link X509Certificate} chain to inspect to find the {@link RSAPublicKey} to represent as a
     *              {@link RsaPublicJwk}.
     * @return the builder coerced as an {@link RsaPublicJwkBuilder}.
     */
    RsaPublicJwkBuilder rsaChain(List<X509Certificate> chain);

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
    RsaPrivateJwkBuilder rsaKeyPair(KeyPair keyPair) throws IllegalArgumentException;
}
