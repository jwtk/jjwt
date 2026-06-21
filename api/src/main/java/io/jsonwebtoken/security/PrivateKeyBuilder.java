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
package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * A builder that allows a {@code PrivateKey} to be transparently associated with a {@link #provider(Provider)} or
 * {@link #publicKey(PublicKey)} if necessary for algorithms that require them.
 *
 * @since 0.12.0
 */
public interface PrivateKeyBuilder extends KeyBuilder<PrivateKey, PrivateKeyBuilder> {

    /**
     * Returns a {@code PrivateKeyBuilder} that produces the specified key, allowing association with a
     * {@link PrivateKeyBuilder#publicKey(PublicKey) publicKey} to obtain public key data if necessary, or a
     * {@link SecretKeyBuilder#provider(Provider) provider} that must be used with the key during cryptographic
     * operations.  For example:
     *
     * <blockquote><pre>
     * PrivateKey key = Keys.builder(privateKey).publicKey(publicKey).provider(mandatoryProvider).build();</pre></blockquote>
     *
     * <p>Cryptographic algorithm implementations can inspect the resulting {@code key} instance and obtain its
     * mandatory {@code Provider} or {@code PublicKey} if necessary.</p>
     *
     * <p>This method is primarily only useful for keys that cannot expose key material, such as PKCS11 or HSM
     * (Hardware Security Module) keys, and require a specific {@code Provider} or public key data to be used
     * during cryptographic operations.</p>
     *
     * @param key the private key to use for cryptographic operations, potentially associated with a configured
     *            {@link Provider} or {@link PublicKey}.
     * @return a new {@code PrivateKeyBuilder} that produces the specified private key, potentially associated with any
     * specified provider or {@code PublicKey}
     * @since JJWT_RELEASE_VERSION
     */
    static PrivateKeyBuilder with(PrivateKey key) {
        return Suppliers.PRIVATE_KEY_BUILDER_FACTORY.apply(key);
    }

    /**
     * Sets the private key's corresponding {@code PublicKey} so that its public key material will be available to
     * algorithms that require it.
     *
     * @param publicKey the private key's corresponding {@code PublicKey}
     * @return the builder for method chaining.
     */
    PrivateKeyBuilder publicKey(PublicKey publicKey);
}
