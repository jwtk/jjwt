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
 * Decoder that ensures any exceptions thrown that are <em>not</em> {@link DecodingException}s are wrapped
 * and re-thrown as a {@code DecodingException}.
 *
 * @since 0.10.0
 */
class ExceptionPropagatingDecoder<T, R> implements Decoder<T, R> {

    private final Decoder<T, R> decoder;

    /**
     * Creates a new instance, wrapping the specified {@code decoder} to invoke during {@link #decode(Object)}.
     *
     * @param decoder the decoder to wrap and call during {@link #decode(Object)}
     */
    ExceptionPropagatingDecoder(Decoder<T, R> decoder) {
        Assert.notNull(decoder, "Decoder cannot be null.");
        this.decoder = decoder;
    }

    /**
     * Decode the specified encoded data, delegating to the wrapped Decoder, wrapping any
     * non-{@link DecodingException} as a {@code DecodingException}.
     *
     * @param t the encoded data
     * @return the decoded data
     * @throws DecodingException if there is an unexpected problem during decoding.
     */
    @Override
    public R decode(T t) throws DecodingException {
        Assert.notNull(t, "Decode argument cannot be null.");
        try {
            return decoder.decode(t);
        } catch (DecodingException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to decode input: " + e.getMessage();
            throw new DecodingException(msg, e);
        }
    }
}
