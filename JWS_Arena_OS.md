# JWS Arena OS

## 개요
JWS Arena OS는 Spring Boot 기반의 **리소스 인식형 인증 런타임**입니다.  
일반적인 JWT/JWS 인증 서버를 넘어서, **서명 알고리즘을 운영체제의 프로세스처럼 취급**하여
CPU, 메모리, 비용 관점에서 스케줄링·제한·제거하는 것을 목표로 합니다.

이 프로젝트는 웹 백엔드 개발자로서 다음 질문에 답하기 위해 설계되었습니다.

> 인증은 기능이 아니라, 비용과 생존의 문제다.

---

## 핵심 목표
- JWS 다중 알고리즘(HS256 / RS256 / ES256) 동시 지원
- 알고리즘별 실제 비용 계측
- 리소스 압박 상황에서의 정책 기반 의사결정
- Spring Boot 내부 라이프사이클과 필터 체인에 대한 깊은 이해 증명

---

## 시스템 컨셉

### 알고리즘 = 프로세스
각 JWS 알고리즘은 단순한 라이브러리가 아니라 **논리적 실행 단위**로 취급됩니다.

- 상태: ACTIVE / THROTTLED / DEAD / RECOVERING
- 자원: CPU budget / Memory budget
- 정책에 의해 스케줄링, 제한, 제거됨

---

## 아키텍처 개요

```
[HTTP Request]
      ↓
OncePerRequestFilter  ← Kernel Entry
      ↓
Algorithm Scheduler
      ↓
JWS Algorithm Worker
      ↓
Controller / Service
```

---

## 주요 구성 요소

### 1. Kernel Layer
- AlgorithmScheduler
- ResourceManager
- PolicyEngine
- Kill / Throttle / Recover 로직

### 2. Algorithm Workers
- HS256Worker
- RS256Worker
- ES256Worker
- 각 알고리즘은 공통 인터페이스 구현

### 3. Control Plane
- Admin API
- Metrics / Leaderboard
- Runtime 상태 조회

---

## 스케줄링 정책

### Cost-Aware Scheduling
각 요청은 다음 비용을 가집니다.

```
cost =
  verify_time * 3
+ token_size  * 1
+ memory_pressure * 2
```

priority = 1 / cost

우선순위가 높은 알고리즘일수록 더 많은 트래픽을 배정받습니다.

---

## 리소스 관리

### 계측 항목
- Base64 decode 시간
- Header parse 시간
- Key lookup 시간
- Signature verify 시간
- 캐시 증가량
- 키 상주 메모리

### 메모리 압박 대응
1. 캐시 TTL 강제 감소
2. 고비용 알고리즘 Throttle
3. 정책에 따른 알고리즘 Kill (Key + Cache 제거)

---

## 장애 및 복구

- DEAD 상태 알고리즘은 신규 토큰 발급 불가
- 기존 토큰 검증은 fallback verifier로 처리
- 조건 충족 시 자동 RECOVERING → ACTIVE 전환

---

## Spring Boot 활용 포인트

- OncePerRequestFilter : 커널 진입점
- SmartLifecycle : 커널 부팅 / 종료
- ApplicationEvent : OOM, ALG_KILLED 이벤트
- @Conditional : 알고리즘 활성 제어
- Micrometer : 비용 메트릭 수집

---

## 설정 예시 (Policy 중심)

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

---

## 출력 예시

```
=== JWS ARENA STATUS ===
HS256  ACTIVE    cpu=12% mem=18MB score=92
ES256  THROTTLE  cpu=28% mem=31MB score=61
RS256  DEAD      cpu=0%  mem=0MB  score=0

Last kill reason: MEMORY_PRESSURE
```

---

## 웹 백엔드 포트폴리오로서의 의미

이 프로젝트는 다음을 명확히 증명합니다.

- Spring Boot 내부 동작 이해
- 인증 시스템을 비용·운영 관점에서 설계하는 능력
- 성능/메모리/보안 트레이드오프 설명 능력
- 실서비스 장애 상황을 가정한 설계 경험

---

## 한 문장 요약
> JWS Arena OS는 인증을 **기능이 아닌 런타임 문제**로 재정의한  
> 고난도 Spring Boot 백엔드 프로젝트입니다.
