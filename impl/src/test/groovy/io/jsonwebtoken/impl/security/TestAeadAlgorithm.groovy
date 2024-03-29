/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.*

class TestAeadAlgorithm implements AeadAlgorithm {

    String id
    int keyBitLength = 256

    @Override
    String getId() {
        return id
    }

    @Override
    void encrypt(AeadRequest request, AeadResult result) throws SecurityException {
    }

    @Override
    void decrypt(DecryptAeadRequest request, OutputStream out) throws SecurityException {
    }

    @Override
    SecretKeyBuilder key() {
        return null
    }

    @Override
    int getKeyBitLength() {
        return keyBitLength
    }
}
