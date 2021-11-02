package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AsymmetricJwk;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public abstract class AbstractAsymmetricJwk<K extends Key> extends AbstractJwk<K> implements AsymmetricJwk<K> {

    static final Field<String> USE = Fields.string("use", "Public Key Use");
    public static final Field<List<X509Certificate>> X5C = Fields.x509Chain("x5c", "X.509 Certificate Chain");
    public static final Field<byte[]> X5T = Fields.bytes("x5t", "X.509 Certificate SHA-1 Thumbprint").build();
    public static final Field<byte[]> X5T_S256 = Fields.bytes("x5t#S256", "X.509 Certificate SHA-256 Thumbprint").build();
    public static final Field<URI> X5U = Fields.uri("x5u", "X.509 URL");
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractJwk.FIELDS, USE, X5C, X5T, X5T_S256, X5U);

    AbstractAsymmetricJwk(JwkContext<K> ctx) {
        super(ctx);
    }

    @Override
    public String getPublicKeyUse() {
        return this.context.getPublicKeyUse();
    }

    @Override
    public URI getX509Url() {
        return this.context.getX509Url();
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return Collections.immutable(this.context.getX509CertificateChain());
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return (byte[])Arrays.copy(this.context.getX509CertificateSha1Thumbprint());
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return (byte[])Arrays.copy(this.context.getX509CertificateSha256Thumbprint());
    }
}
