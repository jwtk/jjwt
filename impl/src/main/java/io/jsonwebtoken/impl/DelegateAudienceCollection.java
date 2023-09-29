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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.ClaimsMutator;
import io.jsonwebtoken.lang.Assert;

import java.util.Collection;

public class DelegateAudienceCollection<P> implements ClaimsMutator.AudienceCollection<P> {

    private final ClaimsMutator.AudienceCollection<?> delegate;

    private final P parent;

    public DelegateAudienceCollection(P parent, ClaimsMutator.AudienceCollection<?> delegate) {
        this.parent = Assert.notNull(parent, "Parent cannot be null.");
        this.delegate = Assert.notNull(delegate, "Delegate cannot be null.");
    }

    @Override
    public P single(String aud) {
        delegate.single(aud);
        return parent;
    }

    @Override
    public ClaimsMutator.AudienceCollection<P> add(String s) {
        delegate.add(s);
        return this;
    }

    @Override
    public ClaimsMutator.AudienceCollection<P> add(Collection<? extends String> c) {
        delegate.add(c);
        return this;
    }

    @Override
    public ClaimsMutator.AudienceCollection<P> clear() {
        delegate.clear();
        return this;
    }

    @Override
    public ClaimsMutator.AudienceCollection<P> remove(String s) {
        delegate.remove(s);
        return this;
    }

    @Override
    public P and() {
        delegate.and(); // allow any cleanup/finalization
        return parent;
    }
}
