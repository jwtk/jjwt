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

import java.security.Key;

/**
 * A message contains a {@link #getPayload() payload} used as input to or output from a cryptographic algorithm.
 *
 * @param <T> The type of payload in the message.
 * @since JJWT_RELEASE_VERSION
 */
public interface Message<T> {

    /**
     * Returns the message payload used as input to or output from a cryptographic algorithm. This is almost always
     * plaintext used for cryptographic signatures or encryption, or ciphertext for decryption, or a {@link Key}
     * instance for wrapping or unwrapping algorithms.
     *
     * @return the message payload used as input to or output from a cryptographic algorithm.
     */
    T getPayload(); //plaintext, ciphertext or Key
}
