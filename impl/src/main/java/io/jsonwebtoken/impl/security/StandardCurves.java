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

import io.jsonwebtoken.impl.lang.DelegatingRegistry;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Curve;

import java.security.Key;

public final class StandardCurves extends DelegatingRegistry<String, Curve> {

    public StandardCurves() {
        super(new IdRegistry<>("Elliptic Curve", Collections.<Curve>of(
                ECCurve.P256,
                ECCurve.P384,
                ECCurve.P521,
                EdwardsCurve.X25519,
                EdwardsCurve.X448,
                EdwardsCurve.Ed25519,
                EdwardsCurve.Ed448
        ), false));
    }

    public static Curve findByKey(Key key) {
        if (key == null) {
            return null;
        }
        Curve curve = ECCurve.findByKey(key);
        if (curve == null) {
            curve = EdwardsCurve.findByKey(key);
        }
        return curve;
    }
}
