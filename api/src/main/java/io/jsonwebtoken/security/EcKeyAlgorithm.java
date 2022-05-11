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
import java.security.interfaces.ECKey;

/**
 * A {@link KeyAlgorithm} that produces JWE Encrypted Keys via Elliptic Curve cryptography.
 *
 * @param <E> the type of Elliptic Curve public key used to obtain the AEAD encryption key
 * @param <D> the type of Elliptic Curve private key used to obtain the AEAD decryption key
 * @since JJWT_RELEASE_VERSION
 */
public interface EcKeyAlgorithm<E extends ECKey & PublicKey, D extends ECKey & PrivateKey> extends KeyAlgorithm<E, D> {
}
