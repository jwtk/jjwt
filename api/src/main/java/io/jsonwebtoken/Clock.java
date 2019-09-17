/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import java.util.Date;

/**
 * A clock represents a time source that can be used when creating and verifying JWTs.
 *
 * @since 0.7.0
 */
public interface Clock {

    /**
     * Returns the clock's current timestamp at the instant the method is invoked.
     *
     * @return the clock's current timestamp at the instant the method is invoked.
     */
    Date now();
}
