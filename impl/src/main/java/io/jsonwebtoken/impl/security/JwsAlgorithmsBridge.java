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

import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import java.security.Key;
import java.util.Collection;

public final class JwsAlgorithmsBridge {

    //prevent instantiation
    private JwsAlgorithmsBridge() {
    }

    //For parser implementation - do not expose outside the impl module
    public static final Registry<String, SecureDigestAlgorithm<?, ?>> REGISTRY;

    static {
        //noinspection RedundantTypeArguments
        REGISTRY = new IdRegistry<>(Collections.<SecureDigestAlgorithm<?, ?>>of(
                new NoneSignatureAlgorithm(),
                new DefaultMacAlgorithm(256),
                new DefaultMacAlgorithm(384),
                new DefaultMacAlgorithm(512),
                new DefaultRsaSignatureAlgorithm(256, 2048),
                new DefaultRsaSignatureAlgorithm(384, 3072),
                new DefaultRsaSignatureAlgorithm(512, 4096),
                new DefaultRsaSignatureAlgorithm(256, 2048, 256),
                new DefaultRsaSignatureAlgorithm(384, 3072, 384),
                new DefaultRsaSignatureAlgorithm(512, 4096, 512),
                new DefaultEllipticCurveSignatureAlgorithm(256),
                new DefaultEllipticCurveSignatureAlgorithm(384),
                new DefaultEllipticCurveSignatureAlgorithm(521)
        ));
    }

    public static Collection<SecureDigestAlgorithm<?, ?>> values() {
        return REGISTRY.values();
    }

    public static SecureDigestAlgorithm<?, ?> findById(String id) {
        return REGISTRY.apply(id);
    }

    public static SecureDigestAlgorithm<?, ?> forId(String id) {
        SecureDigestAlgorithm<?, ?> instance = findById(id);
        if (instance == null) {
            String msg = "Unrecognized JWA SignatureAlgorithm identifier: " + id;
            throw new IllegalArgumentException(msg);
        }
        return instance;
    }

    @SuppressWarnings("unchecked") // TODO: remove for 1.0
    public static <K extends Key> SecureDigestAlgorithm<K, ?> forSigningKey(K key) {
        @SuppressWarnings("deprecation")
        io.jsonwebtoken.SignatureAlgorithm alg = io.jsonwebtoken.SignatureAlgorithm.forSigningKey(key);
        return (SecureDigestAlgorithm<K, ?>) forId(alg.getValue());
    }
}
