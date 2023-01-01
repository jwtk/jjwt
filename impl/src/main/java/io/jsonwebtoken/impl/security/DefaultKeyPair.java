/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyPair;

import java.security.PrivateKey;
import java.security.PublicKey;

public class DefaultKeyPair<A extends PublicKey, B extends PrivateKey> implements KeyPair<A, B> {

    private final A publicKey;
    private final B privateKey;

    private final java.security.KeyPair jdkPair;

    public DefaultKeyPair(A publicKey, B privateKey) {
        this.publicKey = Assert.notNull(publicKey, "PublicKey argument cannot be null.");
        this.privateKey = Assert.notNull(privateKey, "PrivateKey argument cannot be null.");
        this.jdkPair = new java.security.KeyPair(this.publicKey, this.privateKey);
    }

    @Override
    public A getPublic() {
        return this.publicKey;
    }

    @Override
    public B getPrivate() {
        return this.privateKey;
    }

    @Override
    public java.security.KeyPair toJavaKeyPair() {
        return this.jdkPair;
    }
}
