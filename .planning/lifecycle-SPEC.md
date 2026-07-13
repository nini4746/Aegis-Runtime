# SPEC: 알고리즘 라이프사이클 시스템 (minimal testable slice)

## 배경

`Aegis-Runtime.md`가 서명 알고리즘(HS256/RS256/ES256)을 OS 프로세스처럼 다루는 라이프사이클(ACTIVE/THROTTLED/DEAD/RECOVERING + PolicyEngine + kill-order + Leaderboard)을 기술했으나 `src/main`에 미구현. 이 SPEC은 그 코어 가치(알고리즘이 부하에 따라 상태 전이하고 관측 가능)를 결정론적으로 테스트 가능한 최소 슬라이스로 구현한다.

## 자율 결정 기록 (원 스펙 미명세 6건 - 그릴링 대신 방어적 기본값으로 확정)

- **D1 전이 임계값**: PolicyEngine이 순수 함수로 판정. 입력 = 알고리즘별 {avgVerifyMs, failureRate, memoryPressure}. 기본 config(`policy.thresholds`):
  - ACTIVE→THROTTLED: `avgVerifyMs > throttleLatencyMs`(기본 50) **또는** `failureRate > throttleFailureRate`(기본 0.25).
  - THROTTLED→DEAD: THROTTLED 상태로 `deadDwellMs`(기본 5000) 이상 체류 **그리고** `memoryPressure > killMemoryPressure`(기본 0.85). 동시 다수 후보 시 `kill-order`가 우선순위.
  - DEAD→RECOVERING: DEAD 진입 후 `recoverCooldownMs`(기본 10000) 경과.
  - RECOVERING→ACTIVE: RECOVERING 상태에서 `avgVerifyMs < throttleLatencyMs` 그리고 `failureRate < throttleFailureRate`가 1회 샘플 관측.
  - `min-share` 알고리즘(기본 HS256=30)은 **kill 대상에서 제외**(THROTTLE까지만).
- **D2 score 공식**: `score = round(100 * healthFactor * successRate)`, `healthFactor = clamp(1 - avgVerifyMs/scoreLatencyCeilingMs, 0, 1)`(ceiling 기본 100), DEAD = 0. 결정론적.
- **D3 kill vs fallback 모순 해소**: 원 스펙의 "Key + Cache 제거"를 **"검증 캐시 + admission 슬롯 제거, 서명 key material은 보존"**으로 재해석. DEAD = 신규 토큰 admission 거부 + 검증 캐시 무효화. 기존 토큰은 보존된 key로 fallback 경로(캐시·admission 우회 직접 검증) 처리. 이로써 "key 제거 ↔ key로 fallback" 모순 제거. **문서에 명시적 해석으로 기록.**
- **D4 THROTTLED 의미론**: 최소 슬라이스에서는 THROTTLED = 관측 가능 상태 + memoryPressure 높을 때 admission gate에서 우선 거부. 공유 semaphore의 알고리즘별 분할(per-algo permit)은 후속 슬라이스로 연기.
- **D5 clock seam**: 신규 상태머신·샘플러는 `Clock`(또는 `LongSupplier` nanos)을 생성자 주입. 실제 sleep 없이 fake clock으로 dwell/cooldown 테스트.
- **D6 메모리 압력 매핑**: 기존 `CostCalculator.currentMemoryPressure()`(Runtime 기반) 재사용. JVM에서 key 제거로 힙이 실제 회수되진 않으므로, memoryPressure는 kill **트리거**로만 쓰고 kill의 효과는 캐시·admission 정리로 한정(D3와 일관).

## 요구사항

### R1. AlgorithmState + AlgorithmLifecycle (상태머신)
- **검증**: 알고리즘별 상태 홀더가 legal edge만 허용하는 전이를 수행.
- **수용 기준**:
  - [ ] enum `ACTIVE, THROTTLED, DEAD, RECOVERING`.
  - [ ] 불법 전이(예: DEAD→THROTTLED 직접) 거부 또는 무시, 로그.
  - [ ] 생성자에 `Clock`/nanos supplier 주입 (D5).
  - [ ] 마지막 kill 사유(`MEMORY_PRESSURE` 등) 보존.

### R2. PolicyEngine (순수 결정 함수)
- **검증**: `decide(snapshot, config) -> List<Transition>` 가 I/O·clock 없이 결정론적.
- **수용 기준**:
  - [ ] 입력 스냅샷(알고리즘별 avgVerifyMs/failureRate + memoryPressure + 현재 상태 + 상태 진입시각) → 전이 목록.
  - [ ] D1 임계값·kill-order·min-share 규칙 반영.
  - [ ] fake 입력으로 각 전이(ACTIVE→THROTTLED, →DEAD, →RECOVERING, →ACTIVE) 단위 테스트.

### R3. LifecycleRegistry + Sampler(@Scheduled)
- **검증**: 주기적 샘플러가 신호 수집 → PolicyEngine 호출 → 전이 적용.
- **수용 기준**:
  - [ ] 알고리즘별 lifecycle 1개 보유(WorkerRegistry 연계 또는 신규 registry).
  - [ ] 샘플러가 `AlgorithmWorker.avgVerifyTimeMs()` + by_algorithm 성공/실패 신호로 스냅샷 구성.
  - [ ] `@EnableScheduling` + fake clock 주입 가능 구조. 테스트는 샘플러 tick을 직접 호출해 결정론적.

### R4. Kill/Recover 실행 (D3 해석)
- **수용 기준**:
  - [ ] Kill(→DEAD): 해당 알고리즘 검증 캐시 무효화 + 신규 admission 거부 플래그. key material 미삭제.
  - [ ] Recover(→ACTIVE): admission 재허용.
  - [ ] DEAD 알고리즘의 기존 토큰: JwsFilter가 fallback(캐시·admission 우회 직접 검증)로 처리, 신규는 거부.

### R5. JwsFilter 연계
- **수용 기준**:
  - [ ] worker lookup 후 lifecycle 상태 조회.
  - [ ] DEAD → 신규 admission 거부(기존 토큰 fallback 검증), THROTTLED → memoryPressure 높을 때 우선 거부.
  - [ ] 기존 24개 테스트 전부 green (동작 회귀 없음).

### R6. ArenaStatusController (Leaderboard)
- **수용 기준**:
  - [ ] `GET /admin/arena` → 알고리즘별 {algorithm, state, avgVerifyMs, memMB 또는 memoryPressure, score, lastKillReason}.
  - [ ] score = D2 공식.
  - [ ] 라우트 테스트: 상태·score 필드 존재·형식 검증.

### R7. Config
- **수용 기준**:
  - [ ] `@ConfigurationProperties("policy")` 로 thresholds/kill-order/min-share 바인딩.
  - [ ] 기본값 = D1/D2 명시값. application.yml에 policy 블록 추가.

### R8. 게이트
- **수용 기준**:
  - [ ] `mvn test` 전부 green (기존 24 + 신규).
  - [ ] 신규 전이 테스트는 fake clock/fake metrics로 결정론적(실 sleep 0).
  - [ ] CI green.

## 경계

### 범위 내
minimal testable slice: 상태머신, PolicyEngine, sampler, kill/recover(캐시·admission), JwsFilter 연계, Leaderboard endpoint, config.

### 범위 외 (이유)
- per-algo THROTTLE semaphore 분할 (D4, 후속) - 공유 semaphore 대수술 회피.
- DEAD fallback verifier의 정교한 격리 경로 (최소는 직접 검증으로 충분).
- SmartLifecycle 부팅 오케스트레이션 (핵심 가치 아님).
- 분산/멀티노드 상태 (원 스펙에 없음).
- CPU% 실측(스펙 출력의 cpu= 필드) - avgVerifyMs를 cost proxy로 노출, 실 CPU 샘플링은 범위 외.

## must-NOT
- [ ] 기존 JWS 검증/admission/rate-limit 동작을 회귀시키지 않는다(24 테스트 green 유지).
- [ ] kill이 서명 key material을 삭제하지 않는다(D3).
- [ ] 전이 로직에 실 sleep/실시간 의존을 넣지 않는다(fake clock 필수).
- [ ] min-share 보호 알고리즘을 kill하지 않는다.
