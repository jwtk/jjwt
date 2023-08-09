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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;

import java.util.Map;

public interface TokenizedJwt {

    /**
     * Protected header.
     *
     * @return protected header.
     */
    String getProtected();

    /**
     * Returns the Payload for a JWS or Ciphertext for a JWE.
     *
     * @return the Payload for a JWS or Ciphertext for a JWE.
     */
    String getPayload();

    /**
     * Returns the Signature for JWS or AAD Tag for JWE.
     *
     * @return the Signature for JWS or AAD Tag for JWE.
     */
    String getDigest();

    /**
     * Returns a new {@link Header} instance with the specified map state.
     *
     * @param m the header state
     * @return a new header instance.
     */
    Header createHeader(Map<String, ?> m);
}
