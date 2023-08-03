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
import io.jsonwebtoken.security.SecureDigestAlgorithm;

@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.Jwts.SIG
public final class StandardSecureDigestAlgorithms extends DelegatingRegistry<String, SecureDigestAlgorithm<?, ?>> {

    private static final EdSignatureAlgorithm Ed25519 = new EdSignatureAlgorithm(EdwardsCurve.Ed25519);
    private static final EdSignatureAlgorithm Ed448 = new EdSignatureAlgorithm(EdwardsCurve.Ed448);

    public StandardSecureDigestAlgorithms() {
        super(new IdRegistry<>("JWS Digital Signature or MAC", Collections.of(
                new NoneSignatureAlgorithm(),
                new DefaultMacAlgorithm(256),
                new DefaultMacAlgorithm(384),
                new DefaultMacAlgorithm(512),
                new RsaSignatureAlgorithm(256, 2048),
                new RsaSignatureAlgorithm(384, 3072),
                new RsaSignatureAlgorithm(512, 4096),
                new RsaSignatureAlgorithm(256, 2048, 256),
                new RsaSignatureAlgorithm(384, 3072, 384),
                new RsaSignatureAlgorithm(512, 4096, 512),
                new EcSignatureAlgorithm(256),
                new EcSignatureAlgorithm(384),
                new EcSignatureAlgorithm(521),
                new EdSignatureAlgorithm()
        ), false));
    }

    @Override
    public SecureDigestAlgorithm<?, ?> get(Object id) {
        String key = (String) id; // could throw ClassCastException, which is allowed per Map 'get' contract
        if (EdwardsCurve.Ed448.getId().equalsIgnoreCase(key)) {
            return Ed448;
        } else if (EdwardsCurve.Ed25519.getId().equalsIgnoreCase(key)) {
            return Ed25519;
        }
        return super.get(key);
    }

    @Override
    public SecureDigestAlgorithm<?, ?> forKey(String id) throws IllegalArgumentException {
        if (EdwardsCurve.Ed448.getId().equalsIgnoreCase(id)) {
            return Ed448;
        } else if (EdwardsCurve.Ed25519.getId().equalsIgnoreCase(id)) {
            return Ed25519;
        }
        return super.forKey(id);
    }
}
