package io.jsonwebtoken.impl.security;

import java.security.cert.X509Certificate;

public final class KeyUsage {

    private static final boolean[] NO_FLAGS = new boolean[9];

    // Direct from X509Certificate#getKeyUsage() JavaDoc.  For an understand of when/how to use these
    // flags, read https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    private static final int
        digitalSignature = 0,
        nonRepudiation = 1,
        keyEncipherment = 2,
        dataEncipherment = 3,
        keyAgreement = 4,
        keyCertSign = 5,
        cRLSign = 6,
        encipherOnly = 7, //if keyAgreement, then only encipher data during key agreement
        decipherOnly = 8; //if keyAgreement, then only decipher data during key agreement

    private final boolean[] is; //for readability: i.e. is[nonRepudiation] simulates isNonRepudiation, etc.

    public KeyUsage(X509Certificate cert) {
        boolean[] arr = cert != null ? cert.getKeyUsage() : NO_FLAGS;
        this.is = arr != null ? arr : NO_FLAGS;
    }

    public boolean isDigitalSignature() {
        return is[digitalSignature];
    }

    public boolean isNonRepudiation() {
        return is[nonRepudiation];
    }

    public boolean isKeyEncipherment() {
        return is[keyEncipherment];
    }

    public boolean isDataEncipherment() {
        return is[dataEncipherment];
    }

    public boolean isKeyAgreement() {
        return is[keyAgreement];
    }

    public boolean isKeyCertSign() {
        return is[keyCertSign];
    }

    public boolean isCRLSign() {
        return is[cRLSign];
    }

    public boolean isEncipherOnly() {
        return is[encipherOnly];
    }

    public boolean isDecipherOnly() {
        return is[decipherOnly];
    }
}
