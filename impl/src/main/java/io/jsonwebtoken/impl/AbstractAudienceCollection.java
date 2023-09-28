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

import io.jsonwebtoken.ClaimsMutator;
import io.jsonwebtoken.impl.lang.DefaultNestedCollection;

import java.util.Collection;

/**
 * Abstract NestedCollection that requires the AudienceCollection interface to be implemented.
 *
 * @param <P> type of parent to return
 * @since JJWT_RELEASE_VERSION
 */
abstract class AbstractAudienceCollection<P> extends DefaultNestedCollection<String, P>
        implements ClaimsMutator.AudienceCollection<P> {
    protected AbstractAudienceCollection(P parent, Collection<? extends String> seed) {
        super(parent, seed);
    }
}