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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.DelegatingRegistry;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;

@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.Jwts.SIG
public final class StandardSecureDigestAlgorithms extends DelegatingRegistry<String, SecureDigestAlgorithm<?, ?>> {

    public StandardSecureDigestAlgorithms() {
        super(new IdRegistry<>("JWS Digital Signature or MAC", Collections.of(
                NoneSignatureAlgorithm.INSTANCE,
                DefaultMacAlgorithm.HS256,
                DefaultMacAlgorithm.HS384,
                DefaultMacAlgorithm.HS512,
                RsaSignatureAlgorithm.RS256,
                RsaSignatureAlgorithm.RS384,
                RsaSignatureAlgorithm.RS512,
                RsaSignatureAlgorithm.PS256,
                RsaSignatureAlgorithm.PS384,
                RsaSignatureAlgorithm.PS512,
                EcSignatureAlgorithm.ES256,
                EcSignatureAlgorithm.ES384,
                EcSignatureAlgorithm.ES512,
                EdSignatureAlgorithm.INSTANCE
        ), false));
    }

    @SuppressWarnings("unchecked")
    public static <K extends Key> SecureDigestAlgorithm<K, ?> findBySigningKey(K key) {

        SecureDigestAlgorithm<?, ?> alg = null; // null value means no suitable match

        if (key instanceof SecretKey && !(key instanceof Password)) {

            alg = DefaultMacAlgorithm.findByKey(key);

        } else if (key instanceof PrivateKey) {

            PrivateKey pk = (PrivateKey) key;

            alg = RsaSignatureAlgorithm.findByKey(pk);
            if (alg == null) {
                alg = EcSignatureAlgorithm.findByKey(pk);
            }
            if (alg == null && EdSignatureAlgorithm.isSigningKey(pk)) {
                alg = EdSignatureAlgorithm.INSTANCE;
            }
        }

        return (SecureDigestAlgorithm<K, ?>) alg;
    }
}
