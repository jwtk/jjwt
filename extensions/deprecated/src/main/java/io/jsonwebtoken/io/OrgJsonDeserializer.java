/*
 * Copyright (C) 2019 jsonwebtoken.io
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
package io.jsonwebtoken.io;

/**
 * This is a backward compatible version of {@link io.jsonwebtoken.orgjson.io.OrgJsonDeserializer}, which was moved to
 * a different package in version 0.11.0 to avoid a split package issue,
 * see <a href="https://github.com/jwtk/jjwt/issues/399">Issue 399</a>.
 * <p>To migrate, just update your package names.
 * @deprecated Moved to {@link io.jsonwebtoken.orgjson.io.OrgJsonDeserializer}.
 * <p><b>This class will be removed before v1.0</b>
 */
@Deprecated
public class OrgJsonDeserializer extends io.jsonwebtoken.orgjson.io.OrgJsonDeserializer { }
