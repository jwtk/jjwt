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

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.X509Builder;
import io.jsonwebtoken.security.X509Mutator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

//Consolidates logic between AbstractProtectedHeaderBuilder and AbstractAsymmetricJwkBuilder
public class DefaultX509Builder<B extends X509Builder<B>> implements X509Builder<B> {

    private final X509Mutator<?> mutator;

    private final B builder;

    protected boolean computeX509Sha1Thumbprint;

    /**
     * Boolean object indicates 3 states: 1) not configured 2) configured as true, 3) configured as false
     */
    protected Boolean computeX509Sha256Thumbprint = null;

    protected List<X509Certificate> chain;

    protected byte[] sha256Thumbprint;

    private static Function<X509Certificate, byte[]> createGetBytesFunction(Class<? extends RuntimeException> clazz) {
        return Functions.wrapFmt(new CheckedFunction<X509Certificate, byte[]>() {
            @Override
            public byte[] apply(X509Certificate cert) throws Exception {
                return cert.getEncoded();
            }
        }, clazz, "Unable to access X509Certificate encoded bytes necessary to compute thumbprint. Certificate: %s");
    }

    private final Function<X509Certificate, byte[]> GET_X509_BYTES;

    public DefaultX509Builder(X509Mutator<?> mutator, B builder, Class<? extends RuntimeException> getBytesFailedException) {
        this.mutator = Assert.notNull(mutator, "X509Mutator cannot be null.");
        this.builder = Assert.notNull(builder, "X509Builder cannot be null.");
        this.GET_X509_BYTES = createGetBytesFunction(getBytesFailedException);
    }

    @Override
    public B withX509Sha1Thumbprint(boolean enable) {
        this.computeX509Sha1Thumbprint = enable;
        return builder;
    }

    @Override
    public B withX509Sha256Thumbprint(boolean enable) {
        this.computeX509Sha256Thumbprint = enable;
        return builder;
    }

    @Override
    public B setX509Url(URI uri) {
        this.mutator.setX509Url(uri);
        return builder;
    }

    @Override
    public B setX509CertificateChain(List<X509Certificate> chain) {
        this.mutator.setX509CertificateChain(chain);
        this.chain = chain;
        return builder;
    }

    @Override
    public B setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        this.mutator.setX509CertificateSha1Thumbprint(thumbprint);
        return builder;
    }

    @Override
    public B setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        this.mutator.setX509CertificateSha256Thumbprint(thumbprint);
        this.sha256Thumbprint = thumbprint;
        return this.builder;
    }

    private byte[] computeThumbprint(final X509Certificate cert, HashAlgorithm alg) {
        byte[] encoded = GET_X509_BYTES.apply(cert);
        Request<byte[]> request = new DefaultRequest<>(encoded, null, null);
        return alg.hash(request);
    }

    public void apply() {
        X509Certificate firstCert = null;
        if (!Collections.isEmpty(this.chain)) {
            firstCert = this.chain.get(0);
        }

        if (computeX509Sha256Thumbprint == null) { //if not specified, enable by default if possible:
            computeX509Sha256Thumbprint = firstCert != null &&
                    Objects.isEmpty(this.sha256Thumbprint) // no need to compute if already set
                    && !computeX509Sha1Thumbprint; // no need if at least one thumbprint will be set
        }

        if (firstCert != null) {
            if (computeX509Sha1Thumbprint) {
                byte[] thumbprint = computeThumbprint(firstCert, DefaultHashAlgorithm.SHA1);
                setX509CertificateSha1Thumbprint(thumbprint);
            }
            if (computeX509Sha256Thumbprint) {
                byte[] thumbprint = computeThumbprint(firstCert, DefaultHashAlgorithm.SHA256);
                setX509CertificateSha256Thumbprint(thumbprint);
            }
        }
    }
}
