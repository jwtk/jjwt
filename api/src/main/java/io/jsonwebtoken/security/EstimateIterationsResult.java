package io.jsonwebtoken.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EstimateIterationsResult {
    private int estimatedIterations;
    private List<Result> results;

    private boolean estimateSet;

    public EstimateIterationsResult() {
        this.results = new ArrayList<>();
    }

    public EstimateIterationsResult(int numSamples) {
        this.results = new ArrayList<>(numSamples);
    }

    public int getEstimatedIterations() {
        return estimatedIterations;
    }

    public synchronized void setEstimatedIterations(int estimatedIterations) {
        if (estimateSet) {
            throw new UnsupportedOperationException("Estimated iterations already set and can only be set once.");
        }
        estimateSet = true;
        this.estimatedIterations = estimatedIterations;
    }

    public void addResult(int workFactor, long duration) {
        this.results.add(new Result(workFactor, duration));
    }

    public List<Result> getResults() {
        return Collections.unmodifiableList(results);
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
