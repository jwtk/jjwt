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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

/**
 * An {@link AsymmetricKeySignatureAlgorithm} that uses RSA private keys to create signatures, and
 * RSA public keys to verify signatures.
 *
 * @param <S> The type of RSA private key used to create signatures
 * @param <V> The type of RSA public key used to verify signatures
 * @since JJWT_RELEASE_VERSION
 */
public interface RsaSignatureAlgorithm<S extends RSAKey & PrivateKey, V extends RSAKey & PublicKey>
        extends AsymmetricKeySignatureAlgorithm<S, V> {
}
