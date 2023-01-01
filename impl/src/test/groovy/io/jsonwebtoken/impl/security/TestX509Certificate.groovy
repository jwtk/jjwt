/*
 * Copyright (C) 2022 jsonwebtoken.io
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
