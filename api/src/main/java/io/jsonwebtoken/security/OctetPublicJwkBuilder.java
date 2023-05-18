/*
 * Copyright (C) 2019 jsonwebtoken.io
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
 * A {@link PublicJwkBuilder} that creates {@link OctetPublicJwk} instances.
 *
 * @param <A> the type of {@link PublicKey} provided by the created {@link OctetPublicJwk} (e.g. XECPublicKey, EdECPublicKey, etc).
 * @param <B> the type of {@link PrivateKey} that may be paired with the {@link PublicKey} to produce an
 *            {@link OctetPrivateJwk} if desired. For example, XECPrivateKey, EdECPrivateKey, etc.
 * @since JJWT_RELEASE_VERSION
 */
public interface OctetPublicJwkBuilder<A extends PublicKey, B extends PrivateKey>
        extends PublicJwkBuilder<A, B, OctetPublicJwk<A>, OctetPrivateJwk<B, A>, OctetPrivateJwkBuilder<B, A>, OctetPublicJwkBuilder<A, B>> {
}
