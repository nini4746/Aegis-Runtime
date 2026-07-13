# Aegis-Runtime

JWS 검증을 OS 프로세스처럼 다루는 Spring Boot 3.3 런타임. 알고리즘별 워커, 비용 인지 스케줄러, Micrometer 지표를 갖춘 Bearer 인증 게이트웨이.

## 핵심 개념

- **알고리즘 워커**: HS256 / RS256 / ES256 각각이 독립적인 `AlgorithmWorker`. 평균 검증 시간을 EWMA로 유지.
- **비용 공식**: `cost = avgVerifyMs * 3 + tokenSizeKb * 1 + memoryPressure * 100 * 2`
  (명세에서 제시된 verify_time*3 + token_size*1 + memory_pressure*2 가중치 적용)
- **스케줄러**: `Semaphore(permits=8)` 기반. cost가 기준치(`reject-threshold=250`)를 초과하면 비대기 즉시 거절, 그 이하는 cost가 낮을수록 더 오래 큐에서 대기.
- **이벤트**: `JwsVerifiedEvent`, `JwsRejectedEvent` ApplicationEvent 발행.
- **지표**: `aegis.verify.success/failure/latency`, `aegis.scheduler.admitted/rejected/queue_depth/wait` (Micrometer + Prometheus 노출).

## 빌드 및 실행

```bash
mvn test                    # 11건 테스트
mvn spring-boot:run         # 8100 포트
```

엔드포인트:
- `GET /api/ping` — 보호된 샘플 자원 (Bearer 필요)
- `GET /.well-known/jwks.json` — RS256/ES256 공개 키 (RFC 7517)
- `GET /actuator/prometheus` — `aegis_*` 지표

## 호출 예시

```bash
# 1) 테스트 토큰 발급은 JwsVerifyTests에서 사용한 키와 동일한 시크릿이 필요
# 또는 RS256/ES256는 부트마다 새로 생성되므로 외부 발급은 외부 키를 미리 주입해야 함

curl -i localhost:8100/api/ping                                            # 401 (no token)
curl -i localhost:8100/api/ping -H "Authorization: Bearer <jwt>"           # 200 또는 401/503

# 메트릭
curl localhost:8100/actuator/prometheus | grep aegis_
```

## 테스트 (23건)

| 케이스 | 검증 |
|---|---|
| `hs256_valid_token_passes` | HS256 정상 토큰 200 |
| `rs256_valid_token_passes` | RS256 정상 토큰 200 |
| `es256_valid_token_passes` | ES256 정상 토큰 200 |
| `tampered_signature_is_rejected` | 서명 변조 시 401 |
| `expired_token_is_rejected` | 만료 토큰 401 |
| `missing_token_is_rejected` | Bearer 없음 401 |
| `unsupported_algorithm_is_rejected` | `alg=none` 401 |
| `jwks_endpoint_exposes_rs256_and_es256_keys` | `/.well-known/jwks.json` RFC 7517 응답 |
| `hs384_token_is_rejected_by_allowlist` | allowlist 외 알고리즘 거절 |
| `cached_token_does_not_re_invoke_worker` | 토큰 캐시 hit 시 워커 재호출 없음 |
| `concurrent_flood_triggers_some_rejections` | 64 동시 호출 → 일부 통과·일부 거절·rejected 카운터 존재 |

`mvn test` → 23/23 pass (JwsVerifyTests 11, SubjectRateLimiterTest 6, RateLimitFilterTest 4, CostReconcilerTest 2).

## 의도적으로 보류한 항목

- 키 회전(JWKS rotate), kid 동적 라우팅
- 동적 정책(YAML 정책 엔진)
- 분산 환경 공유 큐
- mTLS·OAuth2 통합
- 알고리즘 라이프사이클 상태 머신(ACTIVE/THROTTLED/DEAD/RECOVERING), PolicyEngine, kill-order, Leaderboard — 저장소의 초기 설계 문서(`Aegis-Runtime.md`)가 기술하는 구상이며, `src/main`에는 미구현. 실제로 구현된 것은 워커별 EWMA 비용 계측과 Semaphore 기반 admission뿐이다.

## 최근 추가

- `KeySource` SPI — `PropertyKeySource` 기본 구현, JWKS/KMS 어댑터로 교체 가능
- `TokenVerificationCache` — `ReadWriteLock` + monotonic clock, 시간 역행 방어
- OpenTelemetry 트레이싱 진입점
- `SubjectRateLimiter` — `sub` claim 기반 token-bucket. 단일 자격증명이 검증 큐를 독점하지 못하도록 차단. `aegis.ratelimit.capacity` / `refill-per-sec` 튜닝 가능.
- `CostReconciler` — 사전 예측 cost와 실제 verify time 기반 cost 차이를 `aegis.cost.reconciliation_error_*` 메트릭으로 노출. EWMA 노화 감지에 활용.
- 추가 메트릭: `aegis.verify.by_algorithm{result,algorithm}`, `aegis.verify.rejected_reason{reason,algorithm}`, `aegis.ratelimit.allowed/rejected`.
