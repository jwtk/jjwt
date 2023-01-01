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
import io.jsonwebtoken.security.AeadAlgorithm;

import java.util.Collection;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.EncryptionAlgorithms implementation
public final class EncryptionAlgorithmsBridge {

    // prevent instantiation
    private EncryptionAlgorithmsBridge() {
    }

    //For parser implementation - do not expose outside the impl module:
    public static final Registry<String, AeadAlgorithm> REGISTRY;

    static {
        REGISTRY = new IdRegistry<>(Collections.of(
            (AeadAlgorithm) new HmacAesAeadAlgorithm(128),
            new HmacAesAeadAlgorithm(192),
            new HmacAesAeadAlgorithm(256),
            new GcmAesAeadAlgorithm(128),
            new GcmAesAeadAlgorithm(192),
            new GcmAesAeadAlgorithm(256)
        ));
    }

    public static Collection<AeadAlgorithm> values() {
        return REGISTRY.values();
    }

    public static AeadAlgorithm findById(String id) {
        return REGISTRY.apply(id);
    }

    public static AeadAlgorithm forId(String id) throws IllegalArgumentException {
        AeadAlgorithm alg = findById(id);
        if (alg == null) {
            String msg = "Unrecognized JWA AeadAlgorithm identifier: " + id;
            throw new IllegalArgumentException(msg);
        }
        return alg;
    }
}
