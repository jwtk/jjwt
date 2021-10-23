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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.util.Collection;

/**
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("rawtypes")
public final class KeyAlgorithms {

    //prevent instantiation
    private KeyAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.KeyAlgorithmsBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};
    private static final Class<?>[] ESTIMATE_ITERATIONS_ARG_TYPES = new Class[]{KeyAlgorithm.class, long.class};

    public static Collection<KeyAlgorithm<?, ?>> values() {
        return Classes.invokeStatic(BRIDGE_CLASS, "values", null, (Object[]) null);
    }

    /**
     * Returns the JWE KeyAlgorithm with the specified
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.1">{@code alg} key algorithm identifier</a> or
     * {@code null} if an algorithm for the specified {@code id} cannot be found.
     *
     * @param id a JWE standard {@code alg} key algorithm identifier
     * @return the associated KeyAlgorithm instance or {@code null} otherwise.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.1">RFC 7518, Section 4.1</a>
     */
    public static KeyAlgorithm<?, ?> findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "findById", ID_ARG_TYPES, id);
    }

    public static KeyAlgorithm<?, ?> forId(String id) {
        return forId0(id);
    }

    // do not change this visibility.  Raw type method signature not be publicly exposed
    private static <T> T forId0(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "forId", ID_ARG_TYPES, id);
    }

    public static final KeyAlgorithm<SecretKey, SecretKey> DIRECT = forId0("dir");
    public static final KeyAlgorithm<SecretKey, SecretKey> A128KW = forId0("A128KW");
    public static final KeyAlgorithm<SecretKey, SecretKey> A192KW = forId0("A192KW");
    public static final KeyAlgorithm<SecretKey, SecretKey> A256KW = forId0("A256KW");
    public static final KeyAlgorithm<SecretKey, SecretKey> A128GCMKW = forId0("A128GCMKW");
    public static final KeyAlgorithm<SecretKey, SecretKey> A192GCMKW = forId0("A192GCMKW");
    public static final KeyAlgorithm<SecretKey, SecretKey> A256GCMKW = forId0("A256GCMKW");
    public static final KeyAlgorithm<PasswordKey, PasswordKey> PBES2_HS256_A128KW = forId0("PBES2-HS256+A128KW");
    public static final KeyAlgorithm<PasswordKey, PasswordKey> PBES2_HS384_A192KW = forId0("PBES2-HS384+A192KW");
    public static final KeyAlgorithm<PasswordKey, PasswordKey> PBES2_HS512_A256KW = forId0("PBES2-HS512+A256KW");
    public static final RsaKeyAlgorithm RSA1_5 = forId0("RSA1_5");
    public static final RsaKeyAlgorithm RSA_OAEP = forId0("RSA-OAEP");
    public static final RsaKeyAlgorithm RSA_OAEP_256 = forId0("RSA-OAEP-256");

    //public static final EcKeyAlgorithm ECDH_ES = forId0("ECDH-ES");
    //public static final EcKeyAlgorithm ECDH_ES_A128KW = forId0("ECDH-ES+A128KW");
    //public static final EcKeyAlgorithm ECDH_ES_A192KW = forId0("ECDH-ES+A192KW");
    //public static final EcKeyAlgorithm ECDH_ES_A256KW = forId0("ECDH-ES+A256KW");

    public static int estimateIterations(KeyAlgorithm<PasswordKey, PasswordKey> alg, long desiredMillis) {
        return Classes.invokeStatic(BRIDGE_CLASS, "estimateIterations", ESTIMATE_ITERATIONS_ARG_TYPES, alg, desiredMillis);
    }
}
