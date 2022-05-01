package io.jsonwebtoken.impl;

import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.security.AbstractAsymmetricJwk;
import io.jsonwebtoken.impl.security.AbstractJwk;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Header implementation satisfying shared JWS and JWE header parameter requirements.  Header parameters specific to
 * either JWE or JWS will be defined in respective subclasses.
 *
 * @param <T> specific header type to return from mutation/setter methods for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public abstract class AbstractProtectedHeader<T extends ProtectedHeader<T>> extends DefaultHeader<T> implements ProtectedHeader<T> {

    static final Field<URI> JKU = Fields.uri("jku", "JWK Set URL");
    @SuppressWarnings("rawtypes")
    static final Field<PublicJwk> JWK = Fields.builder(PublicJwk.class).setId("jwk").setName("JSON Web Key").build();
    static final Field<Set<String>> CRIT = Fields.stringSet("crit", "Critical");

    static final Set<Field<?>> FIELDS = Collections.concat(DefaultHeader.FIELDS, CRIT, JKU, JWK, AbstractJwk.KID,
            AbstractAsymmetricJwk.X5U, AbstractAsymmetricJwk.X5C, AbstractAsymmetricJwk.X5T, AbstractAsymmetricJwk.X5T_S256);

    protected AbstractProtectedHeader(Set<Field<?>> fieldSet) {
        super(fieldSet);
    }

    protected AbstractProtectedHeader(Set<Field<?>> fieldSet, Map<String, ?> values) {
        super(fieldSet, values);
    }

    public String getKeyId() {
        return idiomaticGet(AbstractJwk.KID);
    }

    public T setKeyId(String kid) {
        put(AbstractJwk.KID, kid);
        return tthis();
    }

    public URI getJwkSetUrl() {
        return idiomaticGet(JKU);
    }

    public T setJwkSetUrl(URI uri) {
        put(JKU, uri);
        return tthis();
    }

    public PublicJwk<?> getJwk() {
        return idiomaticGet(JWK);
    }

    public T setJwk(PublicJwk<?> jwk) {
        put(JWK, jwk);
        return tthis();
    }

    public URI getX509Url() {
        return idiomaticGet(AbstractAsymmetricJwk.X5U);
    }

    public T setX509Url(URI uri) {
        put(AbstractAsymmetricJwk.X5U, uri);
        return tthis();
    }

    public List<X509Certificate> getX509CertificateChain() {
        return idiomaticGet(AbstractAsymmetricJwk.X5C);
    }

    public T setX509CertificateChain(List<X509Certificate> chain) {
        put(AbstractAsymmetricJwk.X5C, chain);
        return tthis();
    }

    public byte[] getX509CertificateSha1Thumbprint() {
        return idiomaticGet(AbstractAsymmetricJwk.X5T);
    }

    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T, thumbprint);
        return tthis();
    }

    public byte[] getX509CertificateSha256Thumbprint() {
        return idiomaticGet(AbstractAsymmetricJwk.X5T_S256);
    }

    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T_S256, thumbprint);
        return tthis();
    }

    public Set<String> getCritical() {
        return idiomaticGet(CRIT);
    }

    public T setCritical(Set<String> crit) {
        put(CRIT, crit);
        return tthis();
    }
}
