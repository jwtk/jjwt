/*
 * Copyright (C) 2015 jsonwebtoken.io
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

/**
 *  MissingClaimException is a subclass of the {@link InvalidClaimException} that is thrown after it is found that an
 *  expected claim is missing.
 *
 * @since 0.6
 */
public class MissingClaimException extends InvalidClaimException {
    public MissingClaimException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    public MissingClaimException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}
