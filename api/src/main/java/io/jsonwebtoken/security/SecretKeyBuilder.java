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
import java.security.Provider;

/**
 * A {@link KeyBuilder} that creates new secure-random {@link SecretKey}s with a length sufficient to be used by
 * the security algorithm that produced this builder.
 *
 * @since 0.12.0
 */
public interface SecretKeyBuilder extends KeyBuilder<SecretKey, SecretKeyBuilder> {

    /**
     * Returns a {@code SecretKeyBuilder} that produces the specified key, allowing association with a
     * {@link SecretKeyBuilder#provider(Provider) provider} that must be used with the key during cryptographic
     * operations.  For example:
     *
     * <blockquote><pre>
     * SecretKey key = SecretKeyBuilder.with(key).provider(mandatoryProvider).build();</pre></blockquote>
     *
     * <p>Cryptographic algorithm implementations can inspect the resulting {@code key} instance and obtain its
     * mandatory {@code Provider} if necessary.</p>
     *
     * <p>This method is primarily only useful for keys that cannot expose key material, such as PKCS11 or HSM
     * (Hardware Security Module) keys, and require a specific {@code Provider} to be used during cryptographic
     * operations.</p>
     *
     * @param key the secret key to use for cryptographic operations, potentially associated with a configured
     *            {@link Provider}
     * @return a new {@code SecretKeyBuilder} that produces the specified key, potentially associated with any
     * specified provider.
     * @since JJWT_RELEASE_VERSION
     */
    static SecretKeyBuilder with(SecretKey key) {
        return Suppliers.SECRET_KEY_BUILDER_FACTORY.apply(key);
    }
}
