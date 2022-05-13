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
package io.jsonwebtoken.io;

/**
 * A {@code Deserializer} is able to convert serialized data byte arrays into Java objects.
 *
 * @param <T> the type of object to be returned as a result of deserialization.
 * @since 0.10.0
 */
public interface Deserializer<T> {

    /**
     * Convert the specified formatted data byte array into a Java object.
     *
     * @param bytes the formatted data byte array to convert
     * @return the reconstituted Java object
     * @throws DeserializationException if there is a problem converting the byte array to to an object.
     */
    T deserialize(byte[] bytes) throws DeserializationException;
}
