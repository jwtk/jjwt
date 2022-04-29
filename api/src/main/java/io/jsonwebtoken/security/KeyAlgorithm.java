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

import io.jsonwebtoken.Identifiable;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code KeyAlgorithm} produces the {@link SecretKey} used to encrypt or decrypt a JWE. The {@code KeyAlgorithm}
 * used for a particular JWE is {@link #getId() identified} in the JWE's
 * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">{@code alg} header</a>.
 *
 * <p>The {@code KeyAlgorithm} interface is JJWT's idiomatic approach to the JWE specification's
 * <a href="https://tools.ietf.org/html/rfc7516#section-2">{@code Key Management Mode}</a> concept.</p>
 *
 * @since JJWT_RELEASE_VERSION
 * @see <a href="https://tools.ietf.org/html/rfc7516#section-2">RFC 7561, Section 2: JWE Key (Management) Algorithms</a>
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public interface KeyAlgorithm<E extends Key, D extends Key> extends Identifiable {

    KeyResult getEncryptionKey(KeyRequest<E> request) throws SecurityException;

    SecretKey getDecryptionKey(DecryptionKeyRequest<D> request) throws SecurityException;
}
