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

    URI getJwkSetUrl();
    T setJwkSetUrl(URI uri);

    PublicJwk<?> getJwk();
    T setJwk(PublicJwk<?> jwk);

    /**
     * Returns the JWT case-sensitive {@code kid}</a> (Key ID) header value or {@code null} if not present.
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
     */
    T setKeyId(String kid);

    URI getX509Url();
    T setX509Url(URI uri);

    List<X509Certificate> getX509CertificateChain();
    T setX509CertificateChain(List<X509Certificate> chain);

    byte[] getX509CertificateSha1Thumbprint();
    T setX509CertificateSha1Thumbprint(byte[] thumbprint);

    byte[] getX509CertificateSha256Thumbprint();
    T setX509CertificateSha256Thumbprint(byte[] thumbprint);

    Set<String> getCritical();
    T setCritical(Set<String> crit);
}
