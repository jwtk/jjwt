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
import java.security.PublicKey;

/**
 * A {@link PrivateJwkBuilder} that creates {@link OctetPrivateJwk} instances.
 *
 * @param <K> The type of {@link PrivateKey} represented by the constructed {@link OctetPrivateJwk} instance.
 * @param <L> The type of {@link PublicKey} available from the constructed {@link OctetPrivateJwk}'s associated {@link PrivateJwk#toPublicJwk() public JWK} properties.
 * @since JJWT_RELEASE_VERSION
 */
public interface OctetPrivateJwkBuilder<K extends PrivateKey, L extends PublicKey> extends
        PrivateJwkBuilder<K, L, OctetPublicJwk<L>, OctetPrivateJwk<K, L>, OctetPrivateJwkBuilder<K, L>> {
}
