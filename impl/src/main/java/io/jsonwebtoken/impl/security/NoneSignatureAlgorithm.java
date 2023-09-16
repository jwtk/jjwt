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

import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.security.Key;

final class NoneSignatureAlgorithm implements SecureDigestAlgorithm<Key, Key> {

    private static final String ID = "none";

    static final SecureDigestAlgorithm<Key, Key> INSTANCE = new NoneSignatureAlgorithm();

    private NoneSignatureAlgorithm() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public byte[] digest(SecureRequest<byte[], Key> request) throws SecurityException {
        throw new SignatureException("The 'none' algorithm cannot be used to create signatures.");
    }

    @Override
    public boolean verify(VerifySecureDigestRequest<Key> request) throws SignatureException {
        throw new SignatureException("The 'none' algorithm cannot be used to verify signatures.");
    }

    @Override
    public boolean equals(Object obj) {
        return this == obj ||
                (obj instanceof SecureDigestAlgorithm &&
                        ID.equalsIgnoreCase(((SecureDigestAlgorithm<?, ?>) obj).getId()));
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    @Override
    public String toString() {
        return ID;
    }
}
