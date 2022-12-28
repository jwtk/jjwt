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

import javax.crypto.SecretKey;

/**
 * The result of a {@link KeyAlgorithm} encryption key request, containing the resulting
 * {@code JWE encrypted key} and {@code JWE Content Encryption Key (CEK)}, concepts defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-2">JWE Terminology</a>.
 *
 * <p>The result {@link #getPayload() payload} is the {@code JWE encrypted key}, which will be Base64URL-encoded
 * and embedded in the resulting compact JWE string.</p>
 *
 * <p>The result {@link #getKey() key} is the {@code JWE Content Encryption Key (CEK)} which will be used to encrypt
 * the JWE.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyResult extends Message<byte[]>, KeySupplier<SecretKey> {
}
