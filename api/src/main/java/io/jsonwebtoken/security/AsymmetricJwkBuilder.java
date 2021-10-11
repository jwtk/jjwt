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
package io.jsonwebtoken.security;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricJwkBuilder<K extends Key, J extends AsymmetricJwk<K>, T extends AsymmetricJwkBuilder<K, J, T>> extends JwkBuilder<K, J, T> {

    T setPublicKeyUse(String use);

    T setX509CertificateChain(List<X509Certificate> chain);

    T setX509Url(URI uri);

    T withX509KeyUse(boolean enable);

    T withX509Sha1Thumbprint(boolean enable);

    T withX509Sha256Thumbprint(boolean enable);
}
