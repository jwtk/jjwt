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
 * JWK representation of a {@link SecretKey} as defined by the JWA (RFC 7518) specification section on
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4">Parameters for Symmetric Keys</a>.
 *
 * <p>Note that the {@code SecretKey}-specific properties are not available as separate dedicated getter methods, as
 * most Java applications should rarely, if ever, need to access these individual key properties since they typically
 * internal key material and/or serialization details. If you need to access these key properties, it is usually
 * recommended to obtain the corresponding {@link SecretKey} instance returned by {@link #toKey()} and
 * query that instead.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface SecretJwk extends Jwk<SecretKey> {
}
