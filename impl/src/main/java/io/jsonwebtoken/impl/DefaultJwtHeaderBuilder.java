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
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.lang.Collections;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @since 0.12.0
 */
public class DefaultJwtHeaderBuilder extends DefaultJweHeaderBuilder<Jwts.HeaderBuilder> implements Jwts.HeaderBuilder {

    public DefaultJwtHeaderBuilder() {
        super();
    }

    public DefaultJwtHeaderBuilder(DefaultJweHeaderMutator<?> src) {
        super(src);
    }

    // Per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11 and
    // https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13, 'crit' values MUST NOT include:
    //
    // 1. Any header parameter names defined in the JWS or JWE specifications
    // 2. Any header parameter names that are not included in the final header
    private static ParameterMap sanitizeCrit(ParameterMap m, boolean protectedHeader) {
        Set<String> crit = m.get(DefaultProtectedHeader.CRIT);
        if (crit == null) return m; // nothing to do

        //Use a copy constructor to ensure subsequent changes to builder state do not change the constructed header:
        m = new ParameterMap(DefaultJweHeader.PARAMS, m, true);
        m.remove(DefaultProtectedHeader.CRIT.getId()); // remove the unsanitized value

        // Per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11, non-protected headers are not allowed to
        // have a 'crit' header parameter, so we're done, exit early:
        if (!protectedHeader) return m;

        //otherwise we have a protected header (JWS or JWE), so remove unnecessary entries per the RFC sections above:
        Set<String> newCrit = new LinkedHashSet<>(crit);
        for (String val : crit) {
            if (DefaultJweHeader.PARAMS.containsKey(val) || // Defined in JWS or JWE spec, can't be in crit set (#1)
                    !m.containsKey(val)) { // not in the actual header, can't be in crit set either (#2)
                newCrit.remove(val);
            }
        }
        if (!Collections.isEmpty(newCrit)) { // we have a sanitized result per the RFC, so apply it:
            m.put(DefaultProtectedHeader.CRIT, newCrit);
        }
        return m;
    }

    @Override
    public Header build() {

        this.x509.apply(); // apply any X.509 values as necessary based on builder state

        ParameterMap m = this.DELEGATE;

        // Note: conditional sequence matters here: JWE has more specific requirements than JWS, so check that first:
        if (DefaultJweHeader.isCandidate(m)) {
            return new DefaultJweHeader(sanitizeCrit(m, true));
        } else if (DefaultProtectedHeader.isCandidate(m)) {
            return new DefaultJwsHeader(sanitizeCrit(m, true));
        } else {
            // Per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11, 'crit' header is not allowed in
            // non-protected headers:
            return new DefaultHeader(sanitizeCrit(m, false));
        }
    }
}
