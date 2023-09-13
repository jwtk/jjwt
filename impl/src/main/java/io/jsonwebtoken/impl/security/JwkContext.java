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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.impl.X509Context;
import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.KeyOperation;

import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

public interface JwkContext<K extends Key> extends Identifiable, Map<String, Object>, ParameterReadable, Nameable,
        X509Context<JwkContext<K>> {

    JwkContext<K> parameter(Parameter<?> param);

    JwkContext<K> setId(String id);

    JwkContext<K> setIdThumbprintAlgorithm(HashAlgorithm alg);

    HashAlgorithm getIdThumbprintAlgorithm();

    String getType();

    JwkContext<K> setType(String type);

    Set<KeyOperation> getOperations();

    JwkContext<K> setOperations(Collection<KeyOperation> operations);

    String getAlgorithm();

    JwkContext<K> setAlgorithm(String algorithm);

    String getPublicKeyUse();

    JwkContext<K> setPublicKeyUse(String use);

    /**
     * Returns {@code true} if relevant context values indicate JWK use with MAC or digital signature algorithms,
     * {@code false} otherwise.  Specifically {@code true} is only returned if either:
     * <ul>
     *     <li>&quot;sig&quot;.equals({@link #getPublicKeyUse()}), OR</li>
     *     <li>{@link #getOperations()} is not empty and contains either &quot;sign&quot; or &quot;verify&quot;</li>
     * </ul>
     * <p>otherwise {@code false}.</p>
     *
     * @return {@code true} if relevant context values indicate JWK use with MAC or digital signature algorithms,
     * {@code false} otherwise.
     */
    boolean isSigUse();

    K getKey();

    JwkContext<K> setKey(K key);

    PublicKey getPublicKey();

    JwkContext<K> setPublicKey(PublicKey publicKey);

    Provider getProvider();

    JwkContext<K> setProvider(Provider provider);

    SecureRandom getRandom();

    JwkContext<K> setRandom(SecureRandom random);
}
