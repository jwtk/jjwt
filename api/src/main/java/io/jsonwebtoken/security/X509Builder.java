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
package io.jsonwebtoken.security;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Additional X.509-specific builder methods for constructing an associated JWT Header or JWK, enabling method chaining.
 *
 * @param <T> the mutator subtype, for method chaining
 * @since 0.12.0
 */
public interface X509Builder<T extends X509Builder<T>> extends X509Mutator<T> {

    /**
     * If the {@code enable} argument is {@code true}, compute the SHA-1 thumbprint of the first
     * {@link X509Certificate} in the configured {@link #x509Chain(List) x509CertificateChain}, and set
     * the resulting value as the {@link #x509Sha1Thumbprint(byte[])} parameter.
     *
     * <p>If no chain has been configured, or {@code enable} is {@code false}, the builder will not compute nor add a
     * {@code x5t} value.</p>
     *
     * @param enable whether to compute the SHA-1 thumbprint on the first available X.509 Certificate and set
     *               the resulting value as the {@code x5t} value.
     * @return the builder for method chaining.
     */
    T x509Sha1Thumbprint(boolean enable);

    /**
     * If the {@code enable} argument is {@code true}, compute the SHA-256 thumbprint of the first
     * {@link X509Certificate} in the configured {@link #x509Chain(List) x509CertificateChain}, and set
     * the resulting value as the {@link #x509Sha256Thumbprint(byte[])} parameter.
     *
     * <p>If no chain has been configured, or {@code enable} is {@code false}, the builder will not compute nor add a
     * {@code x5t#S256} value.</p>
     *
     * @param enable whether to compute the SHA-256 thumbprint on the first available X.509 Certificate and set
     *               the resulting value as the {@code x5t#S256} value.
     * @return the builder for method chaining.
     */
    T x509Sha256Thumbprint(boolean enable);
}
