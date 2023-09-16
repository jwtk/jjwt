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
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateKeyBuilder extends KeyBuilder<PrivateKey, PrivateKeyBuilder> {

    /**
     * Sets the private key's corresponding {@code PublicKey} so that its public key material will be available to
     * algorithms that require it.
     *
     * @param publicKey the private key's corresponding {@code PublicKey}
     * @return the builder for method chaining.
     */
    PrivateKeyBuilder publicKey(PublicKey publicKey);
}
