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

import io.jsonwebtoken.lang.Assert;

/**
 * Encoder that ensures any exceptions thrown that are <em>not</em> {@link EncodingException}s are wrapped
 * and re-thrown as a {@code EncodingException}.
 *
 * @since 0.10.0
 */
class ExceptionPropagatingEncoder<T, R> implements Encoder<T, R> {

    private final Encoder<T, R> encoder;

    /**
     * Creates a new instance, wrapping the specified {@code encoder} to invoke during {@link #encode(Object)}.
     *
     * @param encoder the encoder to wrap and call during {@link #encode(Object)}
     */
    ExceptionPropagatingEncoder(Encoder<T, R> encoder) {
        Assert.notNull(encoder, "Encoder cannot be null.");
        this.encoder = encoder;
    }

    /**
     * Encoded the specified  data, delegating to the wrapped Encoder, wrapping any
     * non-{@link EncodingException} as an {@code EncodingException}.
     *
     * @param t the data to encode
     * @return the encoded data
     * @throws EncodingException if there is an unexpected problem during encoding.
     */
    @Override
    public R encode(T t) throws EncodingException {
        Assert.notNull(t, "Encode argument cannot be null.");
        try {
            return this.encoder.encode(t);
        } catch (EncodingException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to encode input: " + e.getMessage();
            throw new EncodingException(msg, e);
        }
    }
}
