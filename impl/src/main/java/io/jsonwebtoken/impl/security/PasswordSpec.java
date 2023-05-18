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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.Password;

import java.security.spec.KeySpec;

public class PasswordSpec implements Password, KeySpec {

    private static final String NONE_ALGORITHM = "NONE";
    private static final String DESTROYED_MSG = "Password has been destroyed. Password character array may not be obtained.";
    private static final String ENCODED_DISABLED_MSG =
            "getEncoded() is disabled for Password instances as they are intended to be used " +
                    "with key derivation algorithms only. Because passwords rarely have the length or entropy " +
                    "necessary for secure cryptographic operations such as authenticated hashing or encryption, " +
                    "they are disabled as direct inputs for these operations to help avoid accidental misuse; if " +
                    "you see this exception message, it is likely that the associated Password instance is " +
                    "being used incorrectly.";

    private volatile boolean destroyed;
    private final char[] password;

    public PasswordSpec(char[] password) {
        this.password = Assert.notEmpty(password, "Password character array cannot be null or empty.");
    }

    private void assertActive() {
        if (destroyed) {
            throw new IllegalStateException(DESTROYED_MSG);
        }
    }

    @Override
    public char[] toCharArray() {
        assertActive();
        return this.password.clone();
    }

    @Override
    public String getAlgorithm() {
        return NONE_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return null; // encoding isn't supported, so we return null per the Key#getFormat() JavaDoc
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException(ENCODED_DISABLED_MSG);
    }

    public void destroy() {
        this.destroyed = true;
        java.util.Arrays.fill(password, '\u0000');
    }

    public boolean isDestroyed() {
        return this.destroyed;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(this.password);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof PasswordSpec) {
            PasswordSpec other = (PasswordSpec) obj;
            return Objects.nullSafeEquals(this.password, other.password);
        }
        return false;
    }

    @Override
    public final String toString() {
        return "<redacted>";
    }
}
