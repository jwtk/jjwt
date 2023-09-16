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

import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AsymmetricJwk;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public abstract class AbstractAsymmetricJwk<K extends Key> extends AbstractJwk<K> implements AsymmetricJwk<K> {

    static final Parameter<String> USE = Parameters.string("use", "Public Key Use");
    public static final Parameter<List<X509Certificate>> X5C = Parameters.x509Chain("x5c", "X.509 Certificate Chain");
    public static final Parameter<byte[]> X5T = Parameters.bytes("x5t", "X.509 Certificate SHA-1 Thumbprint").build();
    public static final Parameter<byte[]> X5T_S256 = Parameters.bytes("x5t#S256", "X.509 Certificate SHA-256 Thumbprint").build();
    public static final Parameter<URI> X5U = Parameters.uri("x5u", "X.509 URL");
    static final Set<Parameter<?>> PARAMS = Collections.concat(AbstractJwk.PARAMS, USE, X5C, X5T, X5T_S256, X5U);

    AbstractAsymmetricJwk(JwkContext<K> ctx, List<Parameter<?>> thumbprintParams) {
        super(ctx, thumbprintParams);
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
