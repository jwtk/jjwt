package io.jsonwebtoken.impl.security

import java.security.*
import java.security.cert.*

class TestX509Certificate extends X509Certificate {

    private boolean[] keyUsage = new boolean[9]

    @Override
    void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {

    }

    @Override
    void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {

    }

    @Override
    int getVersion() {
        return 0
    }

    @Override
    BigInteger getSerialNumber() {
        return null
    }

    @Override
    Principal getIssuerDN() {
        return null
    }

    @Override
    Principal getSubjectDN() {
        return null
    }

    @Override
    Date getNotBefore() {
        return null
    }

    @Override
    Date getNotAfter() {
        return null
    }

    @Override
    byte[] getTBSCertificate() throws CertificateEncodingException {
        return new byte[0]
    }

    @Override
    byte[] getSignature() {
        return new byte[0]
    }

    @Override
    String getSigAlgName() {
        return null
    }

    @Override
    String getSigAlgOID() {
        return null
    }

    @Override
    byte[] getSigAlgParams() {
        return new byte[0]
    }

    @Override
    boolean[] getIssuerUniqueID() {
        return new boolean[0]
    }

    @Override
    boolean[] getSubjectUniqueID() {
        return new boolean[0]
    }

    @Override
    boolean[] getKeyUsage() {
        return this.keyUsage
    }

    @Override
    int getBasicConstraints() {
        return 0
    }

    @Override
    byte[] getEncoded() throws CertificateEncodingException {
        return new byte[0]
    }

    @Override
    void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

    }

    @Override
    void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

    }

    @Override
    String toString() {
        return null
    }

    @Override
    PublicKey getPublicKey() {
        return null
    }

    @Override
    boolean hasUnsupportedCriticalExtension() {
        return false
    }

    @Override
    Set<String> getCriticalExtensionOIDs() {
        return null
    }

    @Override
    Set<String> getNonCriticalExtensionOIDs() {
        return null
    }

    @Override
    byte[] getExtensionValue(String oid) {
        return new byte[0]
    }
}
