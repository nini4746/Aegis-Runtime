# CLAUDE.md — Aegis-Runtime (JWS Arena OS)

## Project Overview

Aegis-Runtime (JWS Arena OS) is a Spring Boot-based **resource-aware authentication runtime**. It treats JWS (JSON Web Signature) algorithms as operating system processes — each with CPU/memory budgets, cost-based scheduling, and lifecycle states. The core thesis: **authentication is not a feature, it is a cost and survival problem**.

**Status:** Pre-implementation / design phase. The design specification (`JWS_Arena_OS.md`) is complete; source code implementation has not yet started.

## Repository Structure

```
Aegis-Runtime/
├── CLAUDE.md              # This file — AI assistant guide
├── README.md              # Project title (minimal)
├── JWS_Arena_OS.md        # Full design specification (Korean)
└── .git/
```

### Planned Structure (once implementation begins)

```
Aegis-Runtime/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/aegis/runtime/
│   │   │       ├── kernel/           # AlgorithmScheduler, ResourceManager, PolicyEngine
│   │   │       ├── worker/           # HS256Worker, RS256Worker, ES256Worker
│   │   │       ├── filter/           # OncePerRequestFilter (kernel entry point)
│   │   │       ├── control/          # Admin API, metrics, status endpoints
│   │   │       ├── event/            # OOM, ALG_KILLED application events
│   │   │       ├── config/           # @Conditional beans, policy configuration
│   │   │       └── AegisRuntimeApplication.java
│   │   └── resources/
│   │       └── application.yml       # Policy and scheduling config
│   └── test/
│       └── java/
│           └── com/aegis/runtime/    # Unit and integration tests
├── pom.xml or build.gradle           # Build configuration
├── CLAUDE.md
├── README.md
├── JWS_Arena_OS.md
└── .gitignore
```

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Java (17+) |
| Framework | Spring Boot |
| Build Tool | Maven or Gradle (TBD) |
| Metrics | Micrometer |
| Testing | JUnit 5, Spring Boot Test |

### Key Spring Boot Integration Points

- **OncePerRequestFilter** — Kernel entry point for every HTTP request
- **SmartLifecycle** — Boot/shutdown management of the runtime kernel
- **ApplicationEvent** — Events for OOM, ALG_KILLED, state transitions
- **@Conditional** — Selective algorithm activation/deactivation
- **Micrometer** — Cost metric collection and export

## Architecture

### Request Flow

```
[HTTP Request]
      ↓
OncePerRequestFilter  ← Kernel Entry
      ↓
Algorithm Scheduler   ← Cost-aware routing
      ↓
JWS Algorithm Worker  ← HS256 / RS256 / ES256
      ↓
Controller / Service
```

### Three Layers

1. **Kernel Layer** — Core scheduling and resource management
   - `AlgorithmScheduler` — Routes requests using cost-aware priority
   - `ResourceManager` — Tracks CPU, memory, cache per algorithm
   - `PolicyEngine` — Makes throttle/kill/recover decisions
   - Kill / Throttle / Recover logic

2. **Algorithm Workers** — JWS signature implementations
   - `HS256Worker` (HMAC-SHA256) — lowest cost, symmetric
   - `RS256Worker` (RSA-SHA256) — higher cost, asymmetric
   - `ES256Worker` (ECDSA-SHA256) — moderate cost, asymmetric
   - All workers implement a common interface

3. **Control Plane** — Observability and administration
   - Admin API for algorithm state management
   - Metrics / Leaderboard endpoint
   - Runtime status queries

### Algorithm Lifecycle States

```
ACTIVE → THROTTLED → DEAD → RECOVERING → ACTIVE
```

- **ACTIVE** — Normal operation, accepting requests
- **THROTTLED** — Rate-limited due to resource pressure
- **DEAD** — Killed by policy; no new token issuance; existing tokens verified via fallback
- **RECOVERING** — Transitioning back to ACTIVE when conditions are met

### Cost-Aware Scheduling Formula

```
cost = verify_time * 3 + token_size * 1 + memory_pressure * 2
priority = 1 / cost
```

Higher priority algorithms receive more traffic.

### Resource Metrics Tracked

- Base64 decode time
- Header parse time
- Key lookup time
- Signature verify time
- Cache growth rate
- Key-resident memory

### Memory Pressure Response (escalating)

1. Force-reduce cache TTL
2. Throttle high-cost algorithms
3. Kill algorithms per policy (evict keys + cache)

## Design Document

The full specification is in `JWS_Arena_OS.md` (written in Korean). It covers:
- System concept and objectives
- Architecture and component breakdown
- Scheduling policies and cost formulas
- Resource management and measurement items
- Failure/recovery mechanisms
- Spring Boot integration points
- Configuration examples
- Output format examples

Always refer to this document as the authoritative design reference.

## Development Guidelines

### Code Conventions

- **Java naming:** Standard Java conventions (camelCase methods/variables, PascalCase classes)
- **Package structure:** `com.aegis.runtime.*` organized by layer (kernel, worker, filter, control, event, config)
- **Interface-first design:** All algorithm workers must implement a common interface
- **State machine pattern:** Algorithm lifecycle managed through explicit state transitions
- **Event-driven:** Use Spring's `ApplicationEvent` for cross-cutting concerns (OOM, kills)
- **No magic:** Prefer explicit configuration over convention; use `@Conditional` for toggling

### Implementation Priorities

When building out this project, follow this order:

1. **Project scaffolding** — Spring Boot app, build config, `.gitignore`
2. **Common worker interface** — Define the contract all algorithm workers implement
3. **HS256Worker** — Simplest algorithm, validate the interface design
4. **Kernel filter** — `OncePerRequestFilter` entry point
5. **ResourceManager** — Metric collection per algorithm
6. **AlgorithmScheduler** — Cost calculation and routing
7. **RS256Worker / ES256Worker** — Additional algorithm implementations
8. **PolicyEngine** — Throttle/kill/recover decisions
9. **Control Plane** — Admin API, metrics endpoints, status display
10. **Integration tests** — Full request lifecycle, pressure scenarios

### Configuration Format

Policy configuration uses YAML:

```yaml
policy:
  scheduling:
    mode: cost-aware
    min-share:
      HS256: 30
  memory:
    kill-order:
      - RS256
      - ES256
```

### Expected Output Format

The runtime status display should follow this format:

```
=== JWS ARENA STATUS ===
HS256  ACTIVE    cpu=12% mem=18MB score=92
ES256  THROTTLE  cpu=28% mem=31MB score=61
RS256  DEAD      cpu=0%  mem=0MB  score=0

Last kill reason: MEMORY_PRESSURE
```

## Build & Test

**Not yet configured.** When the build system is set up:

```bash
# Build (Maven)
./mvnw clean package

# Build (Gradle)
./gradlew build

# Run
./mvnw spring-boot:run
# or
./gradlew bootRun

# Test
./mvnw test
# or
./gradlew test
```

## Common Tasks for AI Assistants

### Before making changes
- Read `JWS_Arena_OS.md` for the authoritative design specification
- Understand the three-layer architecture (Kernel, Workers, Control Plane)
- Check the algorithm lifecycle state machine before modifying state logic

### When implementing new components
- Follow the planned package structure under `com.aegis.runtime`
- Ensure algorithm workers implement the common interface
- Add Micrometer metrics for any measurable operation
- Use `ApplicationEvent` for system-level notifications
- Write unit tests alongside implementation

### When modifying scheduling/policy logic
- Preserve the cost formula: `cost = verify_time * 3 + token_size * 1 + memory_pressure * 2`
- Ensure the priority inversion (`priority = 1 / cost`) is maintained
- Respect the configured `kill-order` in policy YAML
- Test under simulated memory pressure scenarios

### Key design constraints
- Algorithms in DEAD state must not issue new tokens
- Existing tokens from DEAD algorithms must still verify via fallback
- RECOVERING algorithms must meet defined conditions before transitioning to ACTIVE
- The `OncePerRequestFilter` is the single entry point — do not bypass it
