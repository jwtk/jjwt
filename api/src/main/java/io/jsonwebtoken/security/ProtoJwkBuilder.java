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
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtoJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>> extends JwkBuilder<K, J, T> {

    SecretJwkBuilder setKey(SecretKey key);

    RsaPublicJwkBuilder setKey(RSAPublicKey key);

    RsaPrivateJwkBuilder setKey(RSAPrivateKey key);

    EcPublicJwkBuilder setKey(ECPublicKey key);

    EcPrivateJwkBuilder setKey(ECPrivateKey key);

    RsaPrivateJwkBuilder setKeyPairRsa(KeyPair keyPair);

    EcPrivateJwkBuilder setKeyPairEc(KeyPair keyPair);
}
