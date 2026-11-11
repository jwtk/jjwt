/*
 * Copyright © 2026 jsonwebtoken.io
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
package io.jsonwebtoken.jackson.testkit;

import java.util.ArrayList;
import java.util.List;

/**
 * A bean with a collection property that has a getter but no setter (common in JAXB-style classes), used to assert
 * that such properties are still populated when reading JSON.
 */
public class SetterlessBean {

    private final List<String> items = new ArrayList<>();

    public List<String> getItems() {
        return items;
    }
}
