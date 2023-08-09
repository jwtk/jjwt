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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;

/**
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("unused") // used via reflection via Jwts.claims()
public final class DefaultClaimsBuilder extends DelegatingClaimsMutator<ClaimsBuilder>
        implements ClaimsBuilder {

    public DefaultClaimsBuilder() {
        super();
    }

    @Override
    public Claims build() {
        // ensure a new instance is returned so that the builder may be re-used:
        return new DefaultClaims(this.DELEGATE);
    }
}
