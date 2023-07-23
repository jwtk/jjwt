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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtHeaderBuilder;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJwtHeaderBuilder extends DefaultJweHeaderBuilder<JwtHeaderBuilder> implements JwtHeaderBuilder {

    @SuppressWarnings("unused") // accessed via reflection from the Jwts.header() method implementation
    public DefaultJwtHeaderBuilder() {
    }

    public DefaultJwtHeaderBuilder(DefaultJweHeaderMutator<?> src) {
        super(src);
    }

    @Override
    public Header build() {

        this.x509.apply(); // apply any X.509 values as necessary based on builder state

        //Use a copy constructor to ensure subsequent changes to builder state do not change the constructed header

        // Note: conditional sequence matters here: JWE has more specific requirements than JWS, so check that first:
        if (DefaultJweHeader.isCandidate(this.params)) {
            return new DefaultJweHeader(this.params);
        } else if (DefaultProtectedHeader.isCandidate(this.params)) {
            return new DefaultJwsHeader(this.params);
        } else {
            return new DefaultHeader(this.params);
        }
    }
}
