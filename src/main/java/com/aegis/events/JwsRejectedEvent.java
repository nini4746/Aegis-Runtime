package com.aegis.events;

public record JwsRejectedEvent(String reason, String algorithm, double cost) {}
