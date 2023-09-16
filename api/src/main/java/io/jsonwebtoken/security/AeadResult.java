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

/**
 * The result of authenticated encryption, providing access to the resulting {@link #getPayload() ciphertext},
 * {@link #getDigest() AAD tag}, and {@link #getInitializationVector() initialization vector}. The AAD tag and
 * initialization vector must be supplied with the ciphertext to decrypt.
 *
 * <p><b>AAD Tag</b></p>
 *
 * {@code AeadResult} inherits {@link DigestSupplier} which is a generic concept for supplying any digest.  The digest
 * in the case of AEAD is called an AAD tag, and it must in turn be supplied for verification during decryption.
 *
 * <p><b>Initialization Vector</b></p>
 *
 * All JWE-standard AEAD algorithms use a secure-random Initialization Vector for safe ciphertext creation, so
 * {@code AeadResult} inherits {@link InitializationVectorSupplier} to make the generated IV available after
 * encryption. This IV must in turn be supplied during decryption.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface AeadResult extends Message<byte[]>, DigestSupplier, InitializationVectorSupplier {
}
