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

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PbeKey extends SecretKey {

    /**
     * Returns a clone of the underlying password character array represented by this Key.  Like all
     * {@code SecretKey} implementations, if you wish to clear the backing password character array for
     * safety/security reasons, call the {@link #destroy()} method, ensuring the key instance can no longer
     * be used.
     *
     * @return a clone of the underlying password character array represented by this Key.
     */
    char[] getPassword();

    /**
     * Returns the number of hashing iterations to perform.
     *
     * @return the number of hashing iterations to perform.
     */
    int getIterations();
}
