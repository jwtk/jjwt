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

import java.security.interfaces.RSAPublicKey;

/**
 * JWK representation of an {@link RSAPublicKey} as defined by the JWA (RFC 7518) specification sections on
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3">Parameters for RSA Keys</a> and
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1">Parameters for RSA Public Keys</a>.
 *
 * <p>Note that the various RSA-specific properties are not available as separate dedicated getter methods, as most Java
 * applications should rarely, if ever, need to access these individual key properties since they typically represent
 * internal key material and/or serialization details. If you need to access these key properties, it is usually
 * recommended to obtain the corresponding {@link RSAPublicKey} instance returned by {@link #toKey()} and
 * query that instead.</p>
 *
 * <p>Even so, because these properties exist and are readable by nature of every JWK being a
 * {@link java.util.Map Map}, they are still accessible via the standard {@code Map} {@link #get(Object) get} method
 * using an appropriate JWK parameter id, for example:</p>
 * <blockquote><pre>
 * jwk.get(&quot;n&quot;);
 * jwk.get(&quot;e&quot;);
 * // ... etc ...</pre></blockquote>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface RsaPublicJwk extends PublicJwk<RSAPublicKey> {
}
