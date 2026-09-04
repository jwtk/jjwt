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
 * JWK representation of an Algorithm Key Pair (AKP) {@link PrivateKey} as defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc9964.html#name-akp-key-type">RFC 9964, Section 5: AKP Key Type</a>.
 *
 * <p>Per <a href="https://www.rfc-editor.org/rfc/rfc9964.html#name-ml-dsa-private-keys">RFC 9964, Section 6</a>, the
 * {@code priv} parameter of an ML-DSA AKP JWK is the 32-byte private key <em>seed</em>, not an expanded private
 * key.  Not every JCA provider retains the seed in a private key's PKCS#8 encoding: the JDK SUN provider on
 * versions 24 through 26 and IBM's OpenJCEPlus provider (on Eclipse OpenJ9) encode ML-DSA private keys as an
 * expanded key only, from which the seed cannot be recovered.  Creating an {@code AkpPrivateJwk} from such a
 * key will throw an {@link InvalidKeyException}; keys parsed from an existing RFC 9964 JWK, keys produced by
 * BouncyCastle, and keys produced by the JDK SUN provider on version 27 or later all retain the seed.</p>
 *
 * <p><b>AKP-specific Properties</b></p>
 *
 * <p>Note that the AKP-specific properties are not available as separate dedicated getter methods, as most Java
 * applications should rarely, if ever, need to access these individual key properties since they typically represent
 * internal key material and/or serialization details. If you need to access these key properties, it is usually
 * recommended to obtain the corresponding {@link PrivateKey} instance returned by {@link #toKey()} and query that
 * instead.</p>
 *
 * <p>Even so, because these properties exist and are readable by nature of every JWK being a
 * {@link java.util.Map Map}, they are still accessible via the standard {@code Map} {@link #get(Object) get} method
 * using an appropriate JWK parameter id, for example:</p>
 *
 * <blockquote><pre>
 * jwk.get(&quot;pub&quot;);
 * jwk.get(&quot;priv&quot;);
 * // ... etc ...</pre></blockquote>
 *
 * @param <K> The type of ML-DSA {@link PrivateKey} represented by this JWK.
 * @param <L> The type of ML-DSA {@link PublicKey} represented by this JWK's corresponding
 *            {@link #toPublicJwk() public JWK}.
 * @since 0.14.0
 */
public interface AkpPrivateJwk<K extends PrivateKey, L extends PublicKey> extends PrivateJwk<K, L, AkpPublicJwk<L>> {
}
