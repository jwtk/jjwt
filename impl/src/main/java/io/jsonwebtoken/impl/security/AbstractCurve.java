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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Curve;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.Key;

abstract class AbstractCurve implements Curve {

    private final String ID;

    private final String JCA_NAME;

    AbstractCurve(String id, String jcaName) {
        this.ID = Assert.notNull(Strings.clean(id), "Curve ID cannot be null or empty.");
        this.JCA_NAME = Assert.notNull(Strings.clean(jcaName), "Curve jcaName cannot be null or empty.");
    }

    @Override
    public String getId() {
        return this.ID;
    }

    public String getJcaName() {
        return this.JCA_NAME;
    }

    @Override
    public int hashCode() {
        return ID.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Curve) {
            Curve curve = (Curve) obj;
            return ID.equals(curve.getId());
        }
        return false;
    }

    @Override
    public String toString() {
        return ID;
    }

    public KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder(this.JCA_NAME);
    }

    /**
     * Returns {@code true} if the specified key is known to represent a point on the curve, {@code false} otherwise.
     *
     * @param key the key to test
     * @return {@code true} if the specified key is known to represent a point on the curve, {@code false} otherwise.
     */
    abstract boolean contains(Key key);
}
