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
import java.security.interfaces.ECPrivateKey;

/**
 * JWK representation of an <a href="https://en.wikipedia.org/wiki/Edwards_curve">Edwards Curve</a>
 * {@link PrivateKey} as defined by RFC 8037, Section 2:
 * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-2">Key Type &quot;OKP&quot;</a>.
 *
 * <p>Unlike the {@link EcPrivateJwk} interface, which only supports
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve">Weierstrass</a>-form {@link ECPrivateKey}s,
 * {@code OctetPrivateJwk} allows for multiple parameterized {@link PrivateKey} types
 * because the JDK supports two different types of Edwards Curve private keys:</p>
 * <ul>
 *     <li><a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/interfaces/XECPrivateKey.html">java.security.interfaces.XECPrivateKey</a>, introduced in JDK 11, and</li>
 *     <li><a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECPrivateKey.html">java.security.interfaces.EdECPrivateKey</a>, introduced in JDK 15.</li>
 * </ul>
 * <p>As such, {@code OctetPrivateJwk} is parameterized to support both key types.</p>
 *
 * <p><b>Earlier JDK Versions</b></p>
 *
 * <p>Even though {@code XECPrivateKey} and {@code EdECPrivateKey} were introduced in JDK 11 and JDK 15 respectively,
 * JJWT supports Octet private JWKs in earlier versions when BouncyCastle is enabled in the application classpath.  When
 * using earlier JDK versions, the {@code OctetPrivateJwk} instance will need be parameterized with the
 * generic {@code PrivateKey} type since the latter key types would not be present.  For example:</p>
 * <blockquote><pre>
 * OctetPrivateJwk&lt;PrivateKey&gt; octetPrivateJwk = getKey();</pre></blockquote>
 *
 * <p><b>OKP-specific Properties</b></p>
 *
 * <p>Note that the various OKP-specific properties are not available as separate dedicated getter methods, as most Java
 * applications should rarely, if ever, need to access these individual key properties since they typically represent
 * internal key material and/or serialization details. If you need to access these key properties, it is usually
 * recommended to obtain the corresponding {@link PrivateKey} instance returned by {@link #toKey()} and
 * query that instead.</p>
 *
 * <p>Even so, because these properties exist and are readable by nature of every JWK being a
 * {@link java.util.Map Map}, they are still accessible via the standard {@code Map} {@link #get(Object) get} method
 * using an appropriate JWK parameter id, for example:</p>
 * <blockquote><pre>
 * jwk.get(&quot;x&quot;);
 * jwk.get(&quot;d&quot;);
 * // ... etc ...</pre></blockquote>
 *
 * @param <K> The type of Edwards-curve {@link PrivateKey} represented by this JWK (e.g. XECPrivateKey, EdECPrivateKey, etc).
 * @param <L> The type of Edwards-curve {@link PublicKey} represented by the JWK's corresponding
 *            {@link #toPublicJwk() public JWK}, for example XECPublicKey, EdECPublicKey, etc.
 * @since JJWT_RELEASE_VERSION
 */
public interface OctetPrivateJwk<K extends PrivateKey, L extends PublicKey> extends PrivateJwk<K, L, OctetPublicJwk<L>> {
}
