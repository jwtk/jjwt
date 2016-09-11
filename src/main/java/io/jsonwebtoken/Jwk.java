package io.jsonwebtoken;

import java.util.Map;

/**
 * A JWK (JSON Web Key) represents a cryptographic key.
 *
 * @param <T> Jwk type
 * @since 0.7
 */
public interface Jwk<T extends Jwk<T>> extends Map<String, Object> {

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.1">Key Type Parameter</a> name: the string literal <b><code>kty</code></b>
     */
    public static final String KEY_TYPE = "kty";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.2">Public Key Use Parameter</a> name: the string literal <b><code>use</code></b>
     */
    public static final String PUBLIC_KEY_USE = "use";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.3">Key Operations Parameter</a> name: the string literal <b><code>key_ops</code></b>
     */
    public static final String KEY_OPERATIONS = "key_ops";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.4">Algorithm Parameter</a> name: the string literal <b><code>alg</code></b>
     */
    public static final String ALGORITHM = "alg";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.5">Key ID Parameter</a> name: the string literal <b><code>kid</code></b>
     */
    public static final String KEY_ID = "kid";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.6">X.509 URL Parameter</a> name: the string literal <b><code>x5u</code></b>
     */
    public static final String X509_URL = "x5u";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.7">X.509 Certificate Chain Parameter</a> name: the string literal <b><code>x5c</code></b>
     */
    public static final String X509_CERT_CHAIN = "x5c";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.8">X.509 Certificate SHA-1 Thumbprint Parameter</a> name: the string literal <b><code>x5t</code></b>
     */
    public static final String X509_CERT_SHA1_THUMBPRINT = "x5t";

    /**
     * JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.9">X.509 Certificate SHA-256 Thumbprint Parameter</a> name: the string literal <b><code>x5t#S256</code></b>
     */
    public static final String X509_CERT_SHA256_THUMBPRINT = "x5t#S256";

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.1">
     * <code>kty</code></a> (Key Type) parameter value or {@code null} if not present.
     *
     * @return the JWK {@code kty} parameter value or {@code null} if not present.
     */
    String getKeyType();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.1"> <code>kty</code></a> (Key Type)
     * parameter value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param kty the JWK {@code kty} parameter value or {@code null} to remove the property from the JSON map.
     * @return the {@code Jwk} instance for method chaining.
     */
    T setKeyType(String kty);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.2"><code>use</code></a>
     * (Public Key Use) parameter value or {@code null} if not present.
     *
     * @return the JWK {@code use} parameter value or {@code null} if not present.
     */
    String getPublicKeyUse();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.2"> <code>use</code></a> (Public Key Use)
     * parameter value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param use the JWK {@code use} parameter value or {@code null} to remove the property from the JSON map.
     * @return the {@code Jwk} instance for method chaining.
     */
    T setPublicKeyUse(String use);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.3"><code>key_ops</code></a>
     * (Key Operations) parameter value or {@code null} if not present.
     *
     * @return the JWK {@code key_ops} parameter value or {@code null} if not present.
     */
    String getKeyOperations();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.3"> <code>key_ops</code></a>
     * (Key Operations) parameter value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param keyOps the JWK {@code key_ops} parameter value or {@code null} to remove the property from the JSON map.
     * @return the {@code Jwk} instance for method chaining.
     */
    T setKeyOperations(String keyOps);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.4"><code>alg</code></a> (Algorithm)
     * parameter value or {@code null} if not present.
     * <p>The algorithm parameter identifies the cryptographic algorithm intended to be used with the key.</p>
     *
     * @return the JWK {@code alg} parameter value or {@code null} if not present.
     */
    String getAlgorithm();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.4"><code>alg</code></a> (Algorithm)
     * parameter value.  A {@code null} value will remove the property from the JSON map.
     * <p>The algorithm parameter identifies the cryptographic algorithm intended to be used with the key.</p>
     *
     * @param alg the JWK {@code alg} parameter value or {@code null} to remove the property from the JSON map.
     * @return the {@code Jwk} instance for method chaining.
     */
    T setAlgorithm(String alg);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.5">
     * <code>kid</code></a> (Key ID) parameter value or {@code null} if not present.
     * <p>The kid parameter value is used to match a specific key.  This is used, for instance, to choose among a set
     * of keys within a JWK Set during key rollover.  When used with JWS or JWE, this value is used to match a JWS or
     * JWE <code>kid</code> Header Parameter value. The structure of the keyId value is unspecified.</p>
     *
     * @return the JWK {@code kid} parameter value or {@code null} if not present.
     */
    String getKeyId();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.5">
     * <code>kid</code></a> (Key ID) parameter value.  A {@code null} value will remove the property from the JSON map.
     * <p>The kid parameter value is used to match a specific key.  This is used, for instance, to choose among a set
     * of keys within a JWK Set during key rollover.  When used with JWS or JWE, this value is used to match a JWS or
     * JWE <code>kid</code> Header Parameter value. The structure of the keyId value is unspecified.</p>
     *
     * @param kid the JWK {@code kid} parameter value or {@code null} to remove the property from the JSON map.
     * @return the {@code Jwk} instance for method chaining.
     */
    T setKeyId(String kid);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.6"><code>x5u</code></a> (X&#46;509 URL)
     * parameter value or {@code null} if not present.
     *
     * @return the JWK {@code x5u} parameter value or {@code null} if not present.
     */
    String getX509Url();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.6"><code>x5u</code></a> (X&#46;509 URL)
     * parameter value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param uri the x509 url (a uri actually)
     * @return the {@code Jwk} instance for method chaining.
     */
    T setX509Url(String uri);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.7"><code>x5c</code></a>
     * (X&#46;509 Certificate Chain) parameter value or {@code null} if not present.
     *
     * @return the JWK {@code x5c} parameter value or {@code null} if not present.
     */
    String getX509CertChain();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.7"><code>x5c</code></a>
     * (X&#46;509 Certificate Chain) parameter value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param chain the x509 certificate chain
     * @return the {@code Jwk} instance for method chaining.
     */
    T setX509CertChain(String chain);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.8"><code>x5t</code></a>
     * (X&#46;509 Certificate SHA-1 Thumbprint) parameter value or {@code null} if not present.
     *
     * @return the JWK {@code x5t} parameter value or {@code null} if not present.
     */
    String getX509CertSha1Thumbprint();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.8"><code>x5t</code></a>
     * (X&#46;509 Certificate SHA-1 Thumbprint) parameter value.  A {@code null} value will remove the property from
     * the JSON map.
     *
     * @param thumbprint the x509 Certificate SHA-1 Thumbprint
     * @return the {@code Jwk} instance for method chaining.
     */
    T setX509CertSha1Thumbprint(String thumbprint);

    /**
     * Returns the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.9"><code>x5t#S256</code></a>
     * (X&#46;509 Certificate SHA-256 Thumbprint) parameter value or {@code null} if not present.
     *
     * @return the JWK {@code x5t#S256} parameter value or {@code null} if not present.
     */
    String getX509CertSha256Thumbprint();

    /**
     * Sets the JWK <a href="https://tools.ietf.org/html/rfc7517#section-4.9"><code>x5t#S256</code></a>
     * (X&#46;509 Certificate SHA-256 Thumbprint) parameter value.  A {@code null} value will remove the property from
     * the JSON map.
     *
     * @param thumbprint the x509 Certificate SHA-256 Thumbprint
     * @return the {@code Jwk} instance for method chaining.
     */
    T setX509CertSha256Thumbprint(String thumbprint);
}
