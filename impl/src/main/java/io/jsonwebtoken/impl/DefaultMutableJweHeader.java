/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public class DefaultMutableJweHeader extends DefaultJweHeaderMutator<DefaultMutableJweHeader> implements JweHeader {

    public DefaultMutableJweHeader(DefaultJweHeaderMutator<?> src) {
        super(src);
    }

    private <T> T get(Parameter<T> param) {
        return this.DELEGATE.get(param);
    }

    // =============================================================
    // JWT Header methods
    // =============================================================

    @Override
    public String getAlgorithm() {
        return get(DefaultHeader.ALGORITHM);
    }

    @Override
    public String getContentType() {
        return get(DefaultHeader.CONTENT_TYPE);
    }

    @Override
    public String getType() {
        return get(DefaultHeader.TYPE);
    }

    @Override
    public String getCompressionAlgorithm() {
        return get(DefaultHeader.COMPRESSION_ALGORITHM);
    }

    // =============================================================
    // Protected Header methods
    // =============================================================

    @Override
    public URI getJwkSetUrl() {
        return get(DefaultProtectedHeader.JKU);
    }

    @Override
    public PublicJwk<?> getJwk() {
        return get(DefaultProtectedHeader.JWK);
    }

    @Override
    public String getKeyId() {
        return get(DefaultProtectedHeader.KID);
    }

    @Override
    public Set<String> getCritical() {
        return get(DefaultProtectedHeader.CRIT);
    }

    // =============================================================
    // X.509 methods
    // =============================================================

    @Override
    public URI getX509Url() {
        return get(DefaultProtectedHeader.X5U);
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(DefaultProtectedHeader.X5C);
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(DefaultProtectedHeader.X5T);
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(DefaultProtectedHeader.X5T_S256);
    }

    // =============================================================
    // JWE Header methods
    // =============================================================

    @Override
    public byte[] getAgreementPartyUInfo() {
        return get(DefaultJweHeader.APU);
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return get(DefaultJweHeader.APV);
    }

    @Override
    public Integer getPbes2Count() {
        return get(DefaultJweHeader.P2C);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return get(DefaultJweHeader.ENCRYPTION_ALGORITHM);
    }

    @Override
    public PublicJwk<?> getEphemeralPublicKey() {
        return get(DefaultJweHeader.EPK);
    }

    @Override
    public byte[] getInitializationVector() {
        return get(DefaultJweHeader.IV);
    }

    @Override
    public byte[] getAuthenticationTag() {
        return get(DefaultJweHeader.TAG);
    }

    @Override
    public byte[] getPbes2Salt() {
        return get(DefaultJweHeader.P2S);
    }
}
