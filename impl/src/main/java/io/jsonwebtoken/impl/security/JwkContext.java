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
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.security.HashAlgorithm;

import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

public interface JwkContext<K extends Key> extends Identifiable, Map<String, Object>, FieldReadable, Nameable,
        X509Context<JwkContext<K>> {

    JwkContext<K> setId(String id);

    JwkContext<K> setIdThumbprintAlgorithm(HashAlgorithm alg);

    HashAlgorithm getIdThumbprintAlgorithm();

    String getType();

    JwkContext<K> setType(String type);

    Set<String> getOperations();

    JwkContext<K> setOperations(Set<String> operations);

    String getAlgorithm();

    JwkContext<K> setAlgorithm(String algorithm);

    String getPublicKeyUse();

    JwkContext<K> setPublicKeyUse(String use);

    K getKey();

    JwkContext<K> setKey(K key);

    PublicKey getPublicKey();

    JwkContext<K> setPublicKey(PublicKey publicKey);

    Provider getProvider();

    JwkContext<K> setProvider(Provider provider);

    SecureRandom getRandom();

    JwkContext<K> setRandom(SecureRandom random);
}
