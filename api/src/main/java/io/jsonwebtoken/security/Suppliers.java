/*
 * Copyright © 2025 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Classes;

import java.io.OutputStream;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Package-private on purpose - this is an internal utility use only.
 *
 * @since JJWT_RELEASE_VERSION
 */
final class Suppliers {

    private Suppliers() { // for coverage
    }

    static final Supplier<Request.Builder<?>> REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultRequest$Builder$Supplier");

    static final Supplier<VerifyDigestRequest.Builder> VERIFY_DIGEST_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultVerifyDigestRequest$Builder$Supplier");

    static final Supplier<SecureRequest.Builder<?, ?>> SECURE_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultSecureRequest$Builder$Supplier");

    static final Supplier<VerifySecureDigestRequest.Builder<?>> VERIFY_SECURE_DIGEST_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultVerifySecureDigestRequest$Builder$Supplier");

    static final Supplier<KeyRequest.Builder<?>> KEY_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultKeyRequest$Builder$Supplier");

    static final Supplier<DecryptionKeyRequest.Builder<?>> DECRYPTION_KEY_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultDecryptionKeyRequest$Builder$Supplier");

    static final Supplier<AeadRequest.Builder> AEAD_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultAeadRequest$Builder$Supplier");

    static final Supplier<DecryptAeadRequest.Builder> DECRYPT_AEAD_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultDecryptAeadRequest$Builder$Supplier");

    static final Function<OutputStream, AeadResult> AEAD_RESULT_FACTORY =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultAeadResult$Factory");
}
