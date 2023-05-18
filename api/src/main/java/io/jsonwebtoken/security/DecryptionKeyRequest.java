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

import java.security.Key;

/**
 * A {@link KeyRequest} to obtain a decryption key that will be used to decrypt a JWE using an {@link AeadAlgorithm}.
 * The AEAD algorithm used for decryption is accessible via {@link #getEncryptionAlgorithm()}.
 *
 * <p>The key used to perform cryptographic operations, for example a direct shared key, or a
 * JWE &quot;key decryption key&quot; will be accessible via {@link #getKey()}. This is always required and
 * never {@code null}.</p>
 *
 * <p>Any encrypted key material (what the JWE specification calls the
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-2">JWE Encrypted Key</a>) will
 * be accessible via {@link #getPayload()}. If present, the {@link KeyAlgorithm} will decrypt it to obtain the resulting
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-2">Content Encryption Key (CEK)</a>.
 * This may be empty however depending on which {@link KeyAlgorithm} was used during JWE encryption.</p>
 *
 * <p>Finally, any public information necessary by the called {@link KeyAlgorithm} to decrypt any
 * {@code JWE Encrypted Key} (such as an initialization vector, authentication tag, ephemeral key, etc) is expected
 * to be available in the JWE protected header, accessible via {@link #getHeader()}.</p>
 *
 * @param <K> the type of {@link Key} used during the request to obtain the resulting decryption key.
 * @since JJWT_RELEASE_VERSION
 */
public interface DecryptionKeyRequest<K extends Key> extends SecureRequest<byte[], K>, KeyRequest<byte[]> {
}
