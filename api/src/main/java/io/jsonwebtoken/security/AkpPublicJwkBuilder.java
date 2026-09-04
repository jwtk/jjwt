/*
 * Copyright © 2026 jsonwebtoken.io
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
import java.security.PublicKey;

/**
 * A {@link PublicJwkBuilder} that creates {@link AkpPublicJwk} instances.
 *
 * @param <A> the type of ML-DSA {@link PublicKey} provided by the created {@link AkpPublicJwk}.
 * @param <B> the type of ML-DSA {@link PrivateKey} that may be paired with the {@link PublicKey} to produce an
 *            {@link AkpPrivateJwk} if desired.
 * @since 0.14.0
 */
public interface AkpPublicJwkBuilder<A extends PublicKey, B extends PrivateKey>
        extends PublicJwkBuilder<A, B, AkpPublicJwk<A>, AkpPrivateJwk<B, A>, AkpPrivateJwkBuilder<B, A>, AkpPublicJwkBuilder<A, B>> {
}
