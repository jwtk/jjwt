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

/**
 * An {@code InitializationVectorSupplier} provides access to the secure-random Initialization Vector used during
 * encryption, which must in turn be presented for use during decryption.  To maintain the security integrity of cryptographic
 * algorithms, a <em>new</em> secure-random Initialization Vector <em>MUST</em> be generated for every individual
 * encryption attempt.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface InitializationVectorSupplier {

    /**
     * Returns the secure-random Initialization Vector used during encryption, which must in turn be presented for
     * use during decryption.
     *
     * @return the secure-random Initialization Vector used during encryption, which must in turn be presented for
     * use during decryption.
     */
    byte[] getInitializationVector();
}
