/*
 * Copyright © 2026 jsonwebtoken.io
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
 * Algorithm parameters that include a payload value required during the cryptographic operation.
 *
 * @param <T> the type of payload
 * @param <P> the subtype returned for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface PayloadParams<T, P extends PayloadParams<T, P>> extends Providable<P>, Randomizable<P> {

    /**
     * Sets the payload used during the cryptographic operation.
     *
     * @param payload the payload used during the cryptographic operation.
     * @return the instance for method chaining.
     */
    P payload(T payload);
}
