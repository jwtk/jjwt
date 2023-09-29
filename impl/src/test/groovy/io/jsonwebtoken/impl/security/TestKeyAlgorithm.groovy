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

import javax.crypto.SecretKey

class TestKeyAlgorithm implements KeyAlgorithm {

    String id

    @Override
    String getId() {
        return id
    }

    @Override
    KeyResult getEncryptionKey(KeyRequest request) throws SecurityException {
        return null
    }

    @Override
    SecretKey getDecryptionKey(DecryptionKeyRequest request) throws SecurityException {
        return null
    }
}
