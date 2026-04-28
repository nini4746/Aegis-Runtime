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
mvn test                    # 8건 테스트
mvn spring-boot:run         # 8100 포트
```

## 호출 예시

```bash
# 1) 테스트 토큰 발급은 JwsVerifyTests에서 사용한 키와 동일한 시크릿이 필요
# 또는 RS256/ES256는 부트마다 새로 생성되므로 외부 발급은 외부 키를 미리 주입해야 함

curl -i localhost:8100/api/ping                                            # 401 (no token)
curl -i localhost:8100/api/ping -H "Authorization: Bearer <jwt>"           # 200 또는 401/503

# 메트릭
curl localhost:8100/actuator/prometheus | grep aegis_
```

## 테스트 (8건)

| 케이스 | 검증 |
|---|---|
| `hs256_valid_token_passes` | HS256 정상 토큰 200 |
| `rs256_valid_token_passes` | RS256 정상 토큰 200 |
| `es256_valid_token_passes` | ES256 정상 토큰 200 |
| `tampered_signature_is_rejected` | 서명 변조 시 401 |
| `expired_token_is_rejected` | 만료 토큰 401 |
| `missing_token_is_rejected` | Bearer 없음 401 |
| `unsupported_algorithm_is_rejected` | `alg=none` 401 |
| `concurrent_flood_triggers_some_rejections` | 64 동시 호출 → 일부 통과·일부 거절·rejected 카운터 존재 |

`mvn test` → 8/8 pass.

## 의도적으로 보류한 항목

- 키 회전(JWKS), kid 라우팅
- 동적 정책(YAML 정책 엔진)
- 분산 환경 공유 큐
- mTLS·OAuth2 통합
- 토큰 캐시(이미 검증된 토큰 재사용)
