/*
 * Copyright © 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Builder;

import java.util.List;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface ParameterBuilder<T> extends Builder<Parameter<T>> {

    ParameterBuilder<T> setId(String id);

    ParameterBuilder<T> setName(String name);

    ParameterBuilder<T> setSecret(boolean secret);

    ParameterBuilder<List<T>> list();

    ParameterBuilder<Set<T>> set();

    ParameterBuilder<T> setConverter(Converter<T, ?> converter);
}
