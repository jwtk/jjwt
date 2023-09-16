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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecretKeyBuilder;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
abstract class CryptoAlgorithm implements Identifiable {

    private final String ID;

    private final String jcaName;

    CryptoAlgorithm(String id, String jcaName) {
        Assert.hasText(id, "id cannot be null or empty.");
        this.ID = id;
        Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.jcaName = jcaName;
    }

    @Override
    public String getId() {
        return this.ID;
    }

    String getJcaName() {
        return this.jcaName;
    }

    static SecureRandom ensureSecureRandom(Request<?> request) {
        SecureRandom random = request != null ? request.getSecureRandom() : null;
        return random != null ? random : Randoms.secureRandom();
    }

    protected JcaTemplate jca() {
        return new JcaTemplate(getJcaName());
    }

    protected JcaTemplate jca(Request<?> request) {
        Assert.notNull(request, "request cannot be null.");
        String jcaName = Assert.hasText(getJcaName(request), "Request jcaName cannot be null or empty.");
        Provider provider = request.getProvider();
        SecureRandom random = ensureSecureRandom(request);
        return new JcaTemplate(jcaName, provider, random);
    }

    protected String getJcaName(Request<?> request) {
        return getJcaName();
    }

    protected SecretKey generateCek(KeyRequest<?> request) {
        AeadAlgorithm enc = Assert.notNull(request.getEncryptionAlgorithm(), "Request encryptionAlgorithm cannot be null.");
        SecretKeyBuilder builder = Assert.notNull(enc.key(), "Request encryptionAlgorithm KeyBuilder cannot be null.");
        SecretKey key = builder.random(request.getSecureRandom()).build();
        return Assert.notNull(key, "Request encryptionAlgorithm SecretKeyBuilder cannot produce null keys.");
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof CryptoAlgorithm) {
            CryptoAlgorithm other = (CryptoAlgorithm) obj;
            return this.ID.equals(other.getId()) && this.jcaName.equals(other.getJcaName());
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + ID.hashCode();
        hash = 31 * hash + jcaName.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        return ID;
    }
}
