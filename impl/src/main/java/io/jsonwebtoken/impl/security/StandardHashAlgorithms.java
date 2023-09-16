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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.DelegatingRegistry;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.HashAlgorithm;

/**
 * Backing implementation for the {@link io.jsonwebtoken.security.Jwks.HASH} implementation.
 *
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.security.Jwks.HASH
public class StandardHashAlgorithms extends DelegatingRegistry<String, HashAlgorithm> {

    public StandardHashAlgorithms() {
        super(new IdRegistry<>("IANA Hash Algorithm", Collections.<HashAlgorithm>of(
                // We don't include DefaultHashAlgorithm.SHA1 here on purpose because 1) it's not in the JWK IANA
                // registry so we don't need to expose it anyway, and 2) we don't want to expose a less-safe algorithm.
                // The SHA1 instance only exists in JJWT's codebase to support RFC-required `x5t`
                // (X.509 SHA-1 Thumbprint) computation - we don't use it anywhere else.
                new DefaultHashAlgorithm("sha-256"),
                new DefaultHashAlgorithm("sha-384"),
                new DefaultHashAlgorithm("sha-512"),
                new DefaultHashAlgorithm("sha3-256"),
                new DefaultHashAlgorithm("sha3-384"),
                new DefaultHashAlgorithm("sha3-512")
        )));
    }
}
