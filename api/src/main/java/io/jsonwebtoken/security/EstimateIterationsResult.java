package io.jsonwebtoken.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EstimateIterationsResult {

    private final int estimatedIterations;
    private final List<Result> results;

    private EstimateIterationsResult(int estimatedIterations, List<Result> results) {
        this.estimatedIterations = estimatedIterations;
        this.results = results;
    }

    public int getEstimatedIterations() {
        return estimatedIterations;
    }

    public List<Result> getResults() {
        return results;
    }

    public static EstimateIterationsResultBuilder builder() {
        return new EstimateIterationsResultBuilder();
    }

    public static EstimateIterationsResultBuilder builder(int numSamples) {
        return new EstimateIterationsResultBuilder(numSamples);
    }

    public static class EstimateIterationsResultBuilder {
        private int estimatedIterations;
        private final List<Result> results;

        public EstimateIterationsResultBuilder() {
            results = new ArrayList<>();
        }

        public EstimateIterationsResultBuilder(int numSamples) {
            results = new ArrayList<>(numSamples);
        }

        public EstimateIterationsResultBuilder addResult(int workFactor, long duration) {
            this.results.add(new Result(workFactor, duration));
            return this;
        }

        public EstimateIterationsResultBuilder setEstimatedIterations(int estimatedIterations) {
            this.estimatedIterations = estimatedIterations;
            return this;
        }

        public EstimateIterationsResult build() {
            return new EstimateIterationsResult(estimatedIterations, Collections.unmodifiableList(results));
        }
    }

    public static final class Result {
        private int workFactor;
        private long duration;

        private Result(){}

        public Result(int workFactor, long duration) {
            this.workFactor = workFactor;
            this.duration = duration;
        }

        public int getWorkFactor() {
            return workFactor;
        }

        public long getDuration() {
            return duration;
        }
    }
}
