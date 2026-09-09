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

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * A {@code Key} suitable for use with password-based key derivation algorithms.
 *
 * <p><b>Usage Warning</b></p>
 *
 * <p>Because raw passwords should never be used as direct inputs for cryptographic operations (such as authenticated
 * hashing or encryption) - and only for derivation algorithms (like password-based encryption) - {@code Password}
 * instances will throw an exception when used in these invalid contexts.  Specifically, calling a
 * {@code Password}'s {@link Password#getEncoded() getEncoded()} method (as would be done automatically by the
 * JCA subsystem during direct cryptographic operations) will throw an
 * {@link UnsupportedOperationException UnsupportedOperationException}.</p>
 *
 * @see #toCharArray()
 * @since 0.12.0
 */
public interface Password extends SecretKey, Destroyable {

    /**
     * Returns a new {@link Password} instance suitable for use with password-based key derivation algorithms.
     *
     * <p><b>Usage Note</b>: Using {@code Password}s outside of key derivation contexts will likely
     * fail. See the {@link Password} JavaDoc for more, and also note the <b>Password Safety</b> section below.</p>
     *
     * <p><b>Password Safety</b></p>
     *
     * <p>Instances returned by this method use a <em>clone</em> of the specified {@code password} character array
     * argument - changes to the argument array will NOT be reflected in the returned key, and vice versa.  If you wish
     * to clear a {@code Password} instance to ensure it is no longer usable, call its {@link Password#destroy()}
     * method will clear/overwrite its internal cloned char array. Also note that each subsequent call to
     * {@link Password#toCharArray()} will also return a new clone of the underlying password character array per
     * standard JCE key behavior.</p>
     *
     * @param password the raw password character array to clone for use with password-based key derivation algorithms.
     * @return a new {@link Password} instance that wraps a new clone of the specified {@code password} character array.
     * @see Password#toCharArray()
     * @since JJWT_RELEASE_VERSION
     */
    static Password of(char[] password) {
        return Suppliers.PASSWORD_FACTORY.apply(password);
    }

    /**
     * Returns a new clone of the underlying password character array for use during derivation algorithms.  Like all
     * {@code SecretKey} implementations, if you wish to clear the backing password character array for
     * safety/security reasons, call the {@link #destroy()} method, ensuring that both the character array is cleared
     * and the {@code Password} instance can no longer be used.
     *
     * <p><b>Usage</b></p>
     *
     * <p>Because a new clone is returned from this method each time it is invoked, it is expected that callers will
     * clear the resulting clone from memory as soon as possible to reduce probability of password exposure.  For
     * example:</p>
     *
     * <pre><code>
     * char[] clonedPassword = aPassword.toCharArray();
     * try {
     *     doSomethingWithPassword(clonedPassword);
     * } finally {
     *     // guarantee clone is cleared regardless of any Exception thrown:
     *     java.util.Arrays.fill(clonedPassword, '\u0000');
     * }
     * </code></pre>
     *
     * @return a clone of the underlying password character array.
     */
    char[] toCharArray();
}
