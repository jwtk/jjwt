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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.DigestAlgorithm;
import io.jsonwebtoken.security.HashAlgorithm;

/**
 * Static class definitions for standard {@link DigestAlgorithm} instances.
 *
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.security.StandardHashAlgorithms
public class StandardHashAlgorithmsBridge extends DelegatingRegistry<HashAlgorithm> {
    public StandardHashAlgorithmsBridge() {
        super(new IdRegistry<>("IANA Hash Algorithm", Collections.of(
                DefaultHashAlgorithm.SHA256
        )));
    }
}
