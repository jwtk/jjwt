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

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

/**
 * JWK representation of an <a href="https://en.wikipedia.org/wiki/Edwards_curve">Edwards Curve</a>
 * {@link PublicKey} as defined by RFC 8037, Section 2:
 * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-2">Key Type &quot;OKP&quot;</a>.
 *
 * <p>Unlike the {@link EcPublicJwk} interface, which only supports
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve">Weierstrass</a>-form {@link ECPublicKey}s,
 * {@code OctetPublicJwk} allows for multiple parameterized {@link PublicKey} types
 * because the JDK supports two different types of Edwards Curve public keys:</p>
 * <ul>
 *     <li><a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/interfaces/XECPublicKey.html">java.security.interfaces.XECPublicKey</a>, introduced in JDK 11, and</li>
 *     <li><a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECPublicKey.html">java.security.interfaces.EdECPublicKey</a>, introduced in JDK 15.</li>
 * </ul>
 * <p>As such, {@code OctetPublicJwk} is parameterized to support both key types.</p>
 *
 * <p><b>Earlier JDK Versions</b></p>
 *
 * <p>Even though {@code XECPublicKey} and {@code EdECPublicKey} were introduced in JDK 11 and JDK 15 respectively,
 * JJWT supports Octet public JWKs in earlier versions when BouncyCastle is enabled in the application classpath.  When
 * using earlier JDK versions, the {@code OctetPublicJwk} instance will need be parameterized with the
 * generic {@code PublicKey} type since the latter key types would not be present.  For example:</p>
 * <pre><code>OctetPublicJwk&lt;PublicKey&gt; octetPublicJwk = getKey();</code></pre>
 *
 * <p><b>OKP-specific Properties</b></p>
 *
 * <p>Note that the various OKP-specific properties are not available as separate dedicated getter methods, as most Java
 * applications should rarely, if ever, need to access these individual key properties since they typically represent
 * internal key material and/or serialization details. If you need to access these key properties, it is usually
 * recommended to obtain the corresponding {@link PublicKey} instance returned by {@link #toKey()} and
 * query that instead.</p>
 *
 * <p>Even so, because these properties exist and are readable by nature of every JWK being a
 * {@link java.util.Map Map}, they are still accessible via the standard {@code Map} {@link #get(Object) get} method
 * using an appropriate JWK parameter id, for example:</p>
 * <blockquote><pre>
 * jwk.get(&quot;x&quot;);
 * // ... etc ...</pre></blockquote>
 *
 * @param <K> The type of Edwards-curve {@link PublicKey} represented by this JWK (e.g. XECPublicKey, EdECPublicKey, etc).
 * @since JJWT_RELEASE_VERSION
 */
public interface OctetPublicJwk<K extends PublicKey> extends PublicJwk<K> {
}
