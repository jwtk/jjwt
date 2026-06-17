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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Package-private on purpose - this is for internal utility use only, see
 * <a href="https://github.com/jwtk/jjwt/issues/988">Issue 988</a> for why this class is necessary.
 *
 * @see <a href="https://github.com/jwtk/jjwt/issues/988">Issue 988</a>.
 * @since JJWT_RELEASE_VERSION
 */
// MAINTAINER NOTE: Do not change this class's visibility modifiers - it is not to be exposed in the public API.
final class Suppliers {

    private Suppliers() { // for coverage
    }

    static final Supplier<DigestRequest.Builder> DIGEST_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultDigestRequest$Builder$Supplier");

    private static final Supplier<SecureDigestRequest.Builder<?>> SECURE_DIGEST_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultSecureDigestRequest$Builder$Supplier");

    static final Supplier<VerifyDigestRequest.Builder> VERIFY_DIGEST_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultVerifyDigestRequest$Builder$Supplier");

    private static final Supplier<VerifySecureDigestRequest.Builder<?>> VERIFY_SECURE_DIGEST_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultVerifySecureDigestRequest$Builder$Supplier");

    static final Supplier<KeyRequest.Builder<?>> KEY_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultKeyRequest$Builder$Supplier");

    static final Supplier<DecryptionKeyRequest.Builder<?>> DECRYPTION_KEY_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultDecryptionKeyRequest$Builder$Supplier");

    static final Supplier<AeadRequest.Builder> AEAD_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultAeadRequest$Builder$Supplier");

    static final Function<OutputStream, AeadResult> AEAD_RESULT_FACTORY =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultAeadResult$Factory");

    static final Supplier<DecryptAeadRequest.Builder> DECRYPT_AEAD_REQUEST_BUILDER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultDecryptAeadRequest$Builder$Supplier");

    static final Function<byte[], InputStream> BYTES_INPUT_STREAM_FACTORY =
            Classes.newInstance("io.jsonwebtoken.impl.io.BytesInputStream$Factory");

    static final Supplier<KeyOperationBuilder> KEY_OPERATION_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultKeyOperationBuilder$Supplier");

    static final Supplier<KeyOperationPolicyBuilder> KEY_OPERATION_POLICY_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultKeyOperationPolicyBuilder$Supplier");

    /* =====================================================================================================
     * JWK utilities
     * ===================================================================================================== */
    static final Function<Jwk<?>, String> UNSAFE_JSON_FUNCTION =
            Classes.newInstance("io.jsonwebtoken.impl.security.UnsafeJsonFunction");

    static final Supplier<DynamicJwkBuilder<?, ?>> JWK_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultDynamicJwkBuilder$Supplier");

    static final Supplier<JwkParserBuilder> JWK_PARSER_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultJwkParserBuilder$Supplier");

    static final Supplier<JwkSetBuilder> JWK_SET_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultJwkSetBuilder$Supplier");

    static final Supplier<JwkSetParserBuilder> JWK_SET_PARSER_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.security.DefaultJwkSetParserBuilder$Supplier");

    @SuppressWarnings("unchecked")
    static <K extends Key> SecureDigestRequest.Builder<K> secureDigestRequestBuilder() {
        return (SecureDigestRequest.Builder<K>) SECURE_DIGEST_REQUEST_BUILDER.get();
    }

    @SuppressWarnings("unchecked")
    static <K extends Key> VerifySecureDigestRequest.Builder<K> verifySecureDigestRequestBuilder() {
        return (VerifySecureDigestRequest.Builder<K>) VERIFY_SECURE_DIGEST_REQUEST_BUILDER.get();
    }
}
