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
 * A request to an {@link AeadAlgorithm} to perform authenticated encryption with a supplied symmetric
 * {@link SecretKey}, allowing for additional data to be authenticated and integrity-protected.
 *
 * @see SecureRequest
 * @see AssociatedDataSupplier
 * @since JJWT_RELEASE_VERSION
 */
public interface AeadRequest extends SecureRequest<byte[], SecretKey>, AssociatedDataSupplier {
}
