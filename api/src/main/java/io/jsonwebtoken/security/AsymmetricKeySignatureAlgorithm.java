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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A {@link SignatureAlgorithm} that works with asymmetric keys. A {@link PrivateKey} is used to create
 * signatures, and a {@link PublicKey} is used to verify signatures.
 *
 * <p><b>Key Pair Generation</b></p>
 *
 * <p>{@code AsymmetricKeySignatureAlgorithm} extends {@link KeyPairBuilderSupplier} to enable
 * {@link KeyPair} generation. Each {@code AsymmetricKeySignatureAlgorithm} instance will return a
 * {@link KeyPairBuilder} that ensures any created key pairs will have a sufficient length and algorithm parameters
 * required by that algorithm.  For example:</p>
 *
 * <blockquote><pre>
 * KeyPair pair = anAsymmetricKeySignatureAlgorithm.keyPairBuilder().build();</pre></blockquote>
 *
 * <p>The resulting {@code pair} is guaranteed to have the correct algorithm parameters and length/strength necessary
 * for that exact {@code anAsymmetricKeySignatureAlgorithm} instance.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricKeySignatureAlgorithm
        extends SignatureAlgorithm<PrivateKey, PublicKey>, KeyPairBuilderSupplier {
}
