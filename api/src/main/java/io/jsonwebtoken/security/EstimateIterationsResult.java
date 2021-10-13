package io.jsonwebtoken.security;

import java.util.ArrayList;
import java.util.List;

public class EstimateIterationsResult {
    private int iterations;
    private List<Integer> workFactors;
    private List<Long> durations;

    public EstimateIterationsResult() {
        this.workFactors = new ArrayList<>();
        this.durations = new ArrayList<>();
    }

    public EstimateIterationsResult(int numSamples) {
        this.workFactors = new ArrayList<>(numSamples);
        this.durations = new ArrayList<>(numSamples);
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public List<Integer> getWorkFactors() {
        return workFactors;
    }

    public void setWorkFactors(List<Integer> workFactors) {
        this.workFactors = workFactors;
    }

    public List<Long> getDurations() {
        return durations;
    }

    public void setDurations(List<Long> durations) {
        this.durations = durations;
    }
}
