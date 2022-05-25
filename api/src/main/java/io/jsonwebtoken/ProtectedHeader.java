package io.jsonwebtoken;

import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * A JWT header that is integrity protected, either by JWS digital signature or JWE AEAD encryption.
 *
 * @param <T> The exact header subtype returned during mutation (setter) operations.
 * @see JwsHeader
 * @see JweHeader
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtectedHeader<T extends ProtectedHeader<T>> extends Header<T> {

    /**
     * Returns the {@code jku} (JWK Set URL) value that refers to a
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWK Set</a>
     * resource containing JSON-encoded Public Keys, or {@code null} if not present.  When present in a
     * {@link JwsHeader}, the first public key in the JWK Set <em>must</em> be the public key used to sign the JWS.
     * When present in a {@link JweHeader}, the first public key in the JWK Set <em>must</em> be the public key used
     * during encryption.
     *
     * @return a URI that refers to a <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWK Set</a>
     * resource for a set of JSON-encoded Public Keys, or {@code null} if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2">JWS JWK Set URL</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4">JWE JWK Set URL</a>
     */
    URI getJwkSetUrl();

    /**
     * Sets the {@code jku} (JWK Set URL) value that refers to a <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWK Set</a>
     * resource containing JSON-encoded Public Keys, or {@code null} if not present.  When set for a
     * {@link JwsHeader}, the first public key in the JWK Set <em>must</em> be the public key used to sign the JWS.
     * When set for a {@link JweHeader}, the first public key in the JWK Set <em>must</em> be the public key used
     * during encryption.
     *
     * @param uri a URI that refers to a <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWK Set</a>
     *            resource containing JSON-encoded Public Keys
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2">JWS JWK Set URL</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4">JWE JWK Set URL</a>
     */
    T setJwkSetUrl(URI uri);

    /**
     * Returns the {@code jwk} (JSON Web Key) associated with the JWT.  When present in a {@link JwsHeader}, the
     * {@code jwk} corresponds to the public key used to digitally sign the JWS.  When present in a {@link JweHeader},
     * the {@code jwk} is the public key to which the JWE was encrypted, and may be used to determine the private key
     * needed to decrypt the JWE.
     *
     * @return the {@code jwk} (JSON Web Key) associated with the header.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3">JWS {@code jwk} (JSON Web Key) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5">JWE {@code jwk} (JSON Web Key) Header Parameter</a>
     */
    PublicJwk<?> getJwk();

    /**
     * Sets the {@code jwk} (JSON Web Key) associated with the JWT.  When set for a {@link JwsHeader}, the
     * {@code jwk} corresponds to the public key used to digitally sign the JWS.  When set for a {@link JweHeader},
     * the {@code jwk} is the public key to which the JWE was encrypted, and may be used to determine the private key
     * needed to decrypt the JWE.
     *
     * @param jwk the {@code jwk} (JSON Web Key) associated with the header.
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3">JWS {@code jwk} (JSON Web Key) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5">JWE {@code jwk} (JSON Web Key) Header Parameter</a>
     */
    T setJwk(PublicJwk<?> jwk);

    /**
     * Returns the JWT case-sensitive {@code kid} (Key ID) header value or {@code null} if not present.
     *
     * <p>The keyId header parameter is a hint indicating which key was used to secure a JWS or JWE.  This
     * parameter allows originators to explicitly signal a change of key to recipients.  The structure of the keyId
     * value is unspecified. Its value is a case-sensitive string.</p>
     *
     * <p>When used with a JWK, the keyId value is used to match a JWK {@code keyId} parameter value.</p>
     *
     * @return the case-sensitive {@code kid} header value or {@code null} if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4">JWS Key ID</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6">JWE Key ID</a>
     */
    String getKeyId();

    /**
     * Sets the JWT case-sensitive {@code kid} (Key ID) header value. A {@code null} value will remove the property
     * from the JSON map.
     *
     * <p>The keyId header parameter is a hint indicating which key was used to secure a JWS or JWE.  This parameter
     * allows originators to explicitly signal a change of key to recipients.  The structure of the keyId value is
     * unspecified. Its value MUST be a case-sensitive string.</p>
     *
     * <p>When used with a JWK, the keyId value is used to match a JWK {@code keyId} parameter value.</p>
     *
     * @param kid the case-sensitive JWS {@code kid} header value or {@code null} to remove the property from the JSON map.
     * @return the header instance for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4">JWS Key ID</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6">JWE Key ID</a>
     */
    T setKeyId(String kid);

    /**
     * Returns the {@code x5u} (X.509 URL) that refers to a resource for the X.509 public key certificate or certificate
     * chain associated with the JWT, or {@code null} if not present.
     *
     * <p>When present in a {@link JwsHeader}, the certificate or certificate chain
     * corresponds to the public key used to digitally sign the JWS.  When present in a {@link JweHeader}, the
     * certificate or certificate chain corresponds to the public key to which the JWE was encrypted, and may be
     * used to determine the private key needed to decrypt the JWE.</p>
     *
     * <p>Each certificate in the resource <em>MUST</em> be in PEM-encoded form, with each certificate delimited as
     * specified in <a href="https://datatracker.ietf.org/doc/html/rfc4945#section-6.1">Section 6.1 of RFC 4945</a>.</p>
     *
     * @return the {@code x5u} (X.509 URL) that refers to a resource for the X.509 public key certificate or certificate
     * chain associated with the JWT.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5">JWS {@code x5u} (X.509 URL) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.7">JWE {@code x5u} (X.509 URL) Header Parameter</a>
     */
    URI getX509Url();

    /**
     * Sets the {@code x5u} (X.509 URL) that refers to a resource for the X.509 public key certificate or certificate
     * chain associated with the JWT. A {@code null} value will remove the property from the JSON map.
     *
     * <p>When set for a {@link JwsHeader}, the certificate or certificate chain
     * corresponds to the public key used to digitally sign the JWS.  When present in a {@link JweHeader}, the
     * certificate or certificate chain corresponds to the public key to which the JWE was encrypted, and may be
     * used to determine the private key needed to decrypt the JWE.</p>
     *
     * <p>Each certificate in the resource <em>MUST</em> be in PEM-encoded form, with each certificate delimited as
     * specified in <a href="https://datatracker.ietf.org/doc/html/rfc4945#section-6.1">Section 6.1 of RFC 4945</a>.</p>
     *
     * @param uri the {@code x5u} (X.509 URL) that refers to a resource for the X.509 public key certificate or certificate
     *            chain associated with the JWT.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5">JWS {@code x5u} (X.509 URL) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.7">JWE {@code x5u} (X.509 URL) Header Parameter</a>
     */
    T setX509Url(URI uri);

    /**
     * Returns the {@code x5c} (X.509 Certificate Chain) associated with the JWT, or {@code null} if not present.
     *
     * <p>When present in a {@link JwsHeader},
     * the first certificate (at list index 0) corresponds to the public key used to digitally sign the JWS.  When
     * present in a {@link JweHeader}, the first certificate (at list index 0) corresponds to the public key to which
     * the JWE was encrypted, and may be used to determine the private key needed to decrypt the JWE.</p>
     *
     * <p>The initial certificate <em>MAY</em> be followed by additional certificates, with each subsequent
     * certificate being the one used to certify the previous one.</p>
     *
     * @return the {@code x5c} (X.509 Certificate Chain) associated with the JWT or {@code null} if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6">JWS {@code x5c} (X.509 Certificate Chain) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8">JWE {@code x5c} (X.509 Certificate Chain) Header Parameter</a>
     */
    List<X509Certificate> getX509CertificateChain();

    /**
     * Sets the {@code x5c} (X.509 Certificate Chain) associated with the JWT. A {@code null} value will remove the
     * property from the JSON map.
     *
     * <p>When set for a {@link JwsHeader},
     * the first certificate (at list index 0) <em>MUST</em> correspond to the public key used to digitally sign the
     * JWS.  When set for a {@link JweHeader}, the first certificate (at list index 0) <em>MUST</em> correspond to the
     * public key to which the JWE was encrypted, and may be used to determine the private key needed to decrypt the
     * JWE.</p>
     *
     * <p>The initial certificate <em>MAY</em> be followed by additional certificates, with each subsequent
     * certificate being the one used to certify the previous one.</p>
     *
     * @param chain the {@code x5c} (X.509 Certificate Chain) associated with the JWT.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6">JWS {@code x5c} (X.509 Certificate Chain) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8">JWE {@code x5c} (X.509 Certificate Chain) Header Parameter</a>
     */
    T setX509CertificateChain(List<X509Certificate> chain);

    /**
     * Returns the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT, or {@code null} if not present.
     *
     * <p>When present in a {@link JwsHeader}, it is the thumbprint of the X.509 certificate corresponding to the key
     * used to digitally sign the JWS.  When present in a {@link JweHeader}, it is the thumbprint of the X.509
     * Certificate corresponding to the public key to which the JWE was encrypted, and may be used to determine the
     * private key needed to decrypt the JWE.</p>
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * @return the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT, or {@code null} if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7">JWS {@code x5t} (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.9">JWE {@code x5t} (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     */
    byte[] getX509CertificateSha1Thumbprint();

    /**
     * Sets the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT. A {@code null} value will remove the
     * property from the JSON map.
     *
     * <p>When set for a {@link JwsHeader}, it is the thumbprint of the X.509 certificate corresponding to the key
     * used to digitally sign the JWS.  When set for a {@link JweHeader}, it is the thumbprint of the X.509
     * Certificate corresponding to the public key to which the JWE was encrypted, and may be used to determine the
     * private key needed to decrypt the JWE.</p>
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * @param thumbprint the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     *                   X.509 Certificate associated with the JWT
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7">JWS {@code x5t} (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.9">JWE {@code x5t} (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     */
    T setX509CertificateSha1Thumbprint(byte[] thumbprint);

    /**
     * Returns the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT, or {@code null} if not present.
     *
     * <p>When present in a {@link JwsHeader}, it is the thumbprint of the X.509 certificate corresponding to the key
     * used to digitally sign the JWS.  When present in a {@link JweHeader}, it is the thumbprint of the X.509
     * Certificate corresponding to the public key to which the JWE was encrypted, and may be used to determine the
     * private key needed to decrypt the JWE.</p>
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * @return the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT, or {@code null} if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8">JWS {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.10">JWE {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     */
    byte[] getX509CertificateSha256Thumbprint();

    /**
     * Sets the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT. A {@code null} value will remove the
     * property from the JSON map.
     *
     * <p>When set for a {@link JwsHeader}, it is the thumbprint of the X.509 certificate corresponding to the key
     * used to digitally sign the JWS.  When set for a {@link JweHeader}, it is the thumbprint of the X.509
     * Certificate corresponding to the public key to which the JWE was encrypted, and may be used to determine the
     * private key needed to decrypt the JWE.</p>
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * @param thumbprint the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the
     *                   DER-encoding of the X.509 Certificate associated with the JWT
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8">JWS {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.10">JWE {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     */
    T setX509CertificateSha256Thumbprint(byte[] thumbprint);

    /**
     * Returns the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     * be understood and supported by the JWT recipient, or {@code null} if not present.
     *
     * @return the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     * be understood and supported by the JWT recipient, or {@code null} if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11">JWS {@code crit} (Critical) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13">JWS {@code crit} (Critical) Header Parameter</a>
     */
    Set<String> getCritical();

    /**
     * Sets the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     * be understood and supported by the JWT recipient. A {@code null} value will remove the
     * property from the JSON map.
     *
     * @param crit the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     *             be understood and supported by the JWT recipient.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11">JWS {@code crit} (Critical) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13">JWS {@code crit} (Critical) Header Parameter</a>
     */
    T setCritical(Set<String> crit);
}
