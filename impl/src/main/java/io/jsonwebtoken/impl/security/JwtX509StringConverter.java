package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class JwtX509StringConverter implements Converter<X509Certificate, String> {

    static final JwtX509StringConverter INSTANCE = new JwtX509StringConverter();

    // Returns a Base64 encoded (NOT Base64Url encoded) string of the cert's encoded byte array per
    // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    // https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8
    // https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
    @Override
    public String applyTo(X509Certificate cert) {
        Assert.notNull(cert, "X509Certificate cannot be null.");
        byte[] der;
        try {
            der = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            String msg = "Unable to access X509Certificate encoded bytes necessary to perform DER " +
                "Base64-encoding. Certificate: {" + cert + "}.  Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
        if (Arrays.length(der) == 0) {
            String msg = "X509Certificate encoded bytes cannot be null or empty.  Certificate: {" + cert + "}.";
            throw new IllegalArgumentException(msg);
        }
        return Encoders.BASE64.encode(der);
    }

    @Override
    public X509Certificate applyFrom(String s) {
        Assert.hasText(s, "X.509 Certificate encoded string cannot be null or empty.");
        try {
            byte[] der = Decoders.BASE64.decode(s); //RFC requires Base64, not Base64Url
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream stream = new ByteArrayInputStream(der);
            return (X509Certificate) cf.generateCertificate(stream);
        } catch (Exception e) {
            String msg = "Unable to convert Base64 String '" + s + "' to X509Certificate instance: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}
