package com.aegis.events;

public record JwsVerifiedEvent(String algorithm, String subject, double cost, long durationNanos) {}
