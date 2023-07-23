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
package io.jsonwebtoken;

import io.jsonwebtoken.lang.Builder;
import io.jsonwebtoken.security.X509Builder;

/**
 * A {@link Builder} that dynamically determines the type of {@link Header} to create based on builder state.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwtHeaderBuilder extends JweHeaderMutator<JwtHeaderBuilder>, X509Builder<JwtHeaderBuilder>,
        Builder<Header> {
}
