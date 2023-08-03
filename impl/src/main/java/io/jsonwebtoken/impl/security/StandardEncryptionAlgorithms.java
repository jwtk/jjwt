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
import io.jsonwebtoken.security.AeadAlgorithm;

@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.Jwts.ENC
public final class StandardEncryptionAlgorithms extends DelegatingRegistry<String, AeadAlgorithm> {

    public StandardEncryptionAlgorithms() {
        super(new IdRegistry<>("JWE Encryption Algorithm", Collections.of(
                (AeadAlgorithm) new HmacAesAeadAlgorithm(128),
                new HmacAesAeadAlgorithm(192),
                new HmacAesAeadAlgorithm(256),
                new GcmAesAeadAlgorithm(128),
                new GcmAesAeadAlgorithm(192),
                new GcmAesAeadAlgorithm(256)), false));
    }
}
