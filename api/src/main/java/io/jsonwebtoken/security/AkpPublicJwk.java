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

import java.security.PublicKey;

/**
 * JWK representation of an Algorithm Key Pair (AKP) {@link PublicKey} as defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc9964.html#name-akp-key-type">RFC 9964, Section 5: AKP Key Type</a>.
 *
 * <p>The {@code AKP} key type carries algorithm-specific key material that has no generic structure of its own; the
 * JWK's {@code alg} value identifies how the material is to be interpreted.  JJWT supports the
 * <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf">FIPS 204</a> ML-DSA algorithms defined by
 * RFC 9964, i.e. {@code ML-DSA-44}, {@code ML-DSA-65} and {@code ML-DSA-87}.</p>
 *
 * <p><b>Runtime Requirements</b></p>
 *
 * <p>ML-DSA reached the JCA in JDK 24 via
 * <a href="https://openjdk.org/jeps/497">JEP 497</a>.  On earlier JDK versions, AKP JWKs are supported when
 * BouncyCastle is enabled in the application classpath.  Because there is no {@code java.security.interfaces} type
 * for ML-DSA keys, {@code AkpPublicJwk} is parameterized with the generic {@link PublicKey} type, for example:</p>
 *
 * <blockquote><pre>
 * AkpPublicJwk&lt;PublicKey&gt; akpPublicJwk = getKey();</pre></blockquote>
 *
 * <p><b>AKP-specific Properties</b></p>
 *
 * <p>Note that the AKP-specific properties are not available as separate dedicated getter methods, as most Java
 * applications should rarely, if ever, need to access these individual key properties since they typically represent
 * internal key material and/or serialization details. If you need to access these key properties, it is usually
 * recommended to obtain the corresponding {@link PublicKey} instance returned by {@link #toKey()} and query that
 * instead.</p>
 *
 * <p>Even so, because these properties exist and are readable by nature of every JWK being a
 * {@link java.util.Map Map}, they are still accessible via the standard {@code Map} {@link #get(Object) get} method
 * using an appropriate JWK parameter id, for example:</p>
 *
 * <blockquote><pre>
 * jwk.get(&quot;pub&quot;);
 * // ... etc ...</pre></blockquote>
 *
 * @param <K> The type of ML-DSA {@link PublicKey} represented by this JWK.
 * @since 0.14.0
 */
public interface AkpPublicJwk<K extends PublicKey> extends PublicJwk<K> {
}
