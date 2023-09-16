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
package io.jsonwebtoken;

import io.jsonwebtoken.lang.Builder;
import io.jsonwebtoken.lang.MapMutator;

/**
 * {@link Builder} used to create an immutable {@link Claims} instance.
 *
 * @see JwtBuilder
 * @see Claims
 * @since JJWT_RELEASE_VERSION
 */
public interface ClaimsBuilder extends MapMutator<String, Object, ClaimsBuilder>, ClaimsMutator<ClaimsBuilder>, Builder<Claims> {
}
