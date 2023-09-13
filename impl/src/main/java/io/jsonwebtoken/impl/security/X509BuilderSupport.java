/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.ParameterMap;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.X509Builder;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

//Consolidates logic between DefaultJwtHeaderBuilder and AbstractAsymmetricJwkBuilder
public class X509BuilderSupport implements X509Builder<X509BuilderSupport> {

    private final ParameterMap map;

    protected boolean computeX509Sha1Thumbprint;

    /**
     * Boolean object indicates 3 states: 1) not configured 2) configured as true, 3) configured as false
     */
    protected Boolean computeX509Sha256Thumbprint = null;

    private static Function<X509Certificate, byte[]> createGetBytesFunction(Class<? extends RuntimeException> clazz) {
        return Functions.wrapFmt(new CheckedFunction<X509Certificate, byte[]>() {
            @Override
            public byte[] apply(X509Certificate cert) throws Exception {
                return cert.getEncoded();
            }
        }, clazz, "Unable to access X509Certificate encoded bytes necessary to compute thumbprint. Certificate: %s");
    }

    private final Function<X509Certificate, byte[]> GET_X509_BYTES;

    public X509BuilderSupport(ParameterMap map, Class<? extends RuntimeException> getBytesFailedException) {
        this.map = Assert.notNull(map, "ParameterMap cannot be null.");
        this.GET_X509_BYTES = createGetBytesFunction(getBytesFailedException);
    }

    @Override
    public X509BuilderSupport withX509Sha1Thumbprint(boolean enable) {
        this.computeX509Sha1Thumbprint = enable;
        return this;
    }

    @Override
    public X509BuilderSupport withX509Sha256Thumbprint(boolean enable) {
        this.computeX509Sha256Thumbprint = enable;
        return this;
    }

    @Override
    public X509BuilderSupport x509Url(URI uri) {
        this.map.put(AbstractAsymmetricJwk.X5U.getId(), uri);
        return this;
    }

    @Override
    public X509BuilderSupport x509CertificateChain(List<X509Certificate> chain) {
        this.map.put(AbstractAsymmetricJwk.X5C.getId(), chain);
        return this;
    }

    @Override
    public X509BuilderSupport x509CertificateSha1Thumbprint(byte[] thumbprint) {
        this.map.put(AbstractAsymmetricJwk.X5T.getId(), thumbprint);
        return this;
    }

    @Override
    public X509BuilderSupport x509CertificateSha256Thumbprint(byte[] thumbprint) {
        this.map.put(AbstractAsymmetricJwk.X5T_S256.getId(), thumbprint);
        return this;
    }

    private byte[] computeThumbprint(final X509Certificate cert, HashAlgorithm alg) {
        byte[] encoded = GET_X509_BYTES.apply(cert);
        Request<byte[]> request = new DefaultRequest<>(encoded, null, null);
        return alg.digest(request);
    }

    public void apply() {
        List<X509Certificate> chain = this.map.get(AbstractAsymmetricJwk.X5C);
        X509Certificate firstCert = null;
        if (!Collections.isEmpty(chain)) {
            firstCert = chain.get(0);
        }

        Boolean computeX509Sha256 = this.computeX509Sha256Thumbprint;
        if (computeX509Sha256 == null) { //if not specified, enable by default if possible:
            computeX509Sha256 = firstCert != null &&
                    !computeX509Sha1Thumbprint && // no need if at least one thumbprint will be set
                    Objects.isEmpty(this.map.get(AbstractAsymmetricJwk.X5T_S256)); // no need if already set
        }

        if (firstCert != null) {
            if (computeX509Sha1Thumbprint) {
                byte[] thumbprint = computeThumbprint(firstCert, DefaultHashAlgorithm.SHA1);
                x509CertificateSha1Thumbprint(thumbprint);
            }
            if (computeX509Sha256) {
                byte[] thumbprint = computeThumbprint(firstCert, Jwks.HASH.SHA256);
                x509CertificateSha256Thumbprint(thumbprint);
            }
        }
    }
}
