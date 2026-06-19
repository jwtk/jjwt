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
package io.jsonwebtoken;

import io.jsonwebtoken.lang.Classes;

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

    static final Supplier<JwtBuilder> JWT_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtBuilder$Supplier");

    static final Supplier<JwtParserBuilder> JWT_PARSER_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtParserBuilder$Supplier");

    static final Supplier<Jwts.HeaderBuilder> HEADER_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtHeaderBuilder$Supplier");

    static final Supplier<ClaimsBuilder> CLAIMS_BUILDER_SUPPLIER =
            Classes.newInstance("io.jsonwebtoken.impl.DefaultClaimsBuilder$Supplier");

    private Suppliers() { // for coverage
    }
}
