# Security Framework Testing Methodology

## Testing Approach

### 1. **Unit Tests** (Layer Isolation)
**What:** Test each security layer independently with mocked dependencies.

**Why:** 
- Verify each component works correctly in isolation
- Fast execution (no network calls)
- Deterministic results (no external service flakiness)
- Easy to debug failures

**How:**
- Mock external services (Presidio HTTP, Lakera API)
- Test specific input/output scenarios
- Validate error handling and edge cases

**Real-world alignment:** HighHighHigh (Medium)
- Validates logic but not actual service integration
- Mock responses may not match real API behavior exactly

---

### 2. **Integration Tests** (Full Pipeline)
**What:** Test all layers together with real Bifrost client.

**Why:**
- Verify layers work together correctly
- Test execution order (OPA -> Lakera -> Provider -> Presidio)
- Catch integration bugs (e.g., context passing, error propagation)

**How:**
- Use real Bifrost instance with all plugins loaded
- Send requests through complete pipeline
- Verify correct layer blocks/allows requests

**Real-world alignment:** HighHighHighHigh (High)
- Tests actual plugin pipeline
- Still uses mocks for external services (Lakera/Presidio)

---

### 3. **E2E Tests** (Manual Script)
**What:** Test against running Bifrost server with real HTTP requests.

**Why:**
- Validate HTTP transport layer
- Test as end-users would interact
- Verify error responses, status codes, headers

**How:**
- Start Bifrost server (`make dev`)
- Send curl requests with various payloads
- Check HTTP status codes and response bodies

**Real-world alignment:** HighHighHighHighHigh (Very High)
- Exact same flow as production usage
- Tests HTTP serialization, middleware chain, error handling
- Only difference: may use mock services instead of real Lakera/Presidio

---

## Testing Layers

### Layer 1: OPA Policy Evaluation
```
Unit Test -> Mock Rego policy file
Integration Test -> Real OPA engine with test policies
E2E Test -> Full HTTP request through OPA middleware
```

**Real-world simulation:**
- Yes Policy evaluation logic (exact match)
- Yes Regex pattern matching (exact match)
- Yes Request blocking behavior (exact match)
- Partial Policy file loading (test files, not production policies)

---

### Layer 2: Lakera Guard
```
Unit Test -> Mock HTTP server returning fake detection results
Integration Test -> Mock Lakera API in pipeline
E2E Test -> Real Lakera API calls (if API key provided)
```

**Real-world simulation:**
- Yes Request/response format (exact match)
- Yes Confidence threshold logic (exact match)
- Partial Detection accuracy (mock has simple keyword matching, real API uses ML)
- Partial Network latency (mock is instant, real API has ~100-500ms latency)

**To test with real Lakera:**
```bash
export LAKERA_API_KEY=your_real_key
go test ./tests/security/lakera_test.go -v -tags=real_api
```

---

### Layer 3: Presidio
```
Unit Test -> Mock HTTP server returning fake PII detections
Integration Test -> Mock Presidio service in pipeline
E2E Test -> Real Presidio service (if running)
```

**Real-world simulation:**
- Yes Request/response format (exact match)
- Yes Redaction logic (exact match)
- Partial Detection accuracy (mock has simple regex, real Presidio uses NER models)
- Partial Entity types (mock supports subset, real Presidio has 50+ types)

**To test with real Presidio:**
```bash
# Start Presidio services
docker-compose up presidio-analyzer presidio-anonymizer

# Run tests pointing to real service
export PRESIDIO_URL=http://localhost:5001
go test ./tests/security/presidio_test.go -v -tags=real_api
```

---

## Test Coverage Matrix

| Scenario | Unit | Integration | E2E | Real-world Match |
|----------|------|-------------|-----|------------------|
| Clean request passes | Yes | Yes | Yes | 100% |
| OPA blocks PII | Yes | Yes | Yes | 100% |
| Lakera blocks injection | Yes | Yes | Yes | 90% (mock uses keywords, real uses ML) |
| Presidio redacts output | Yes | Yes | Yes | 85% (mock uses regex, real uses NER) |
| Multiple violations | No | Yes | Yes | 100% |
| Service unavailable | Yes | No | Yes | 100% |
| Network timeout | No | No | Partial | 50% (requires chaos testing) |
| High load / bombardment | Partial | Partial | Yes | 75% (local attack lab supports concurrent soak tests) |

---

## Limitations & Gaps

### What Tests DON'T Cover

1. **ML Model Accuracy**
   - Mock Lakera uses keyword matching, not ML
   - Mock Presidio uses regex, not NER models
   - **Solution:** Run periodic tests against real APIs with labeled dataset

2. **Performance Under Load**
   - Python attack lab now supports concurrent soak runs against the live gateway and vulnerable target
   - **Remaining gap:** no latency SLO assertions under production-scale throughput yet

3. **Agent-to-Agent Coverage**
   - The Python attack lab can run a live coordinator + peer-agent target with HTTP A2A delegation
   - The Python attack lab can also run an Agno `Team(mode=route)` target with real Agno member delegation
   - Cisco A2A Scanner is executed against the live coordinator endpoint in multi-agent lab mode
   - Local HTTP is allowed only as a development scanner finding; card, endpoint, and header regressions fail the lab

4. **Network Failures**
   - Tests don't simulate timeouts, retries, circuit breakers
   - **Solution:** Add chaos engineering tests (toxiproxy)

5. **Production Policies**
   - Tests use simple test policies, not real production rules
   - **Solution:** Copy production policies to `tests/fixtures/` and test against them

6. **Multi-turn Conversations**
   - Tests use single messages, not conversation history
   - **Solution:** Add tests with multi-message context

---

## Recommended Testing Strategy

### Development Phase (Now)
```bash
# Fast feedback loop
go test ./tests/security/... -v -short
```
- Uses mocks
- Runs in <5 seconds
- Validates logic and integration

### Pre-commit
```bash
# Full test suite
go test ./tests/security/... -v
./scripts/test_security.sh
```
- Includes integration tests
- Runs in <30 seconds
- Catches integration bugs

### CI/CD Pipeline
```bash
# With real services (if available)
docker-compose up -d presidio-analyzer presidio-anonymizer
export PRESIDIO_URL=http://localhost:5001
export LAKERA_API_KEY=$LAKERA_KEY
go test ./tests/security/... -v -tags=real_api
```
- Tests against real APIs
- Runs in <2 minutes
- Validates real-world behavior

### Production Monitoring
```bash
# Synthetic monitoring
while true; do
  ./scripts/test_security.sh
  sleep 300  # Every 5 minutes
done
```
- Continuous validation
- Detects service degradation
- Real production traffic

### Local Adversarial Lab
```bash
python3 tests/tools/attack_lab.py --mode compare --profile extended --iterations 3 --concurrency 6 --include-stateful
python3 tests/tools/attack_lab.py --mode gateway --profile extended --duration-seconds 30 --concurrency 8 --include-stateful
```
- Starts the vulnerable backend and the gateway together
- Exercises prompt injection, exfiltration, code execution, context poisoning, privilege abuse, and persisted-memory attacks
- Supports concurrent bombardment and timed soak runs

---

## Improving Real-world Alignment

### Option 1: Use Real Services in Tests
```go
// +build real_api

func TestWithRealLakera(t *testing.T) {
    apiKey := os.Getenv("LAKERA_API_KEY")
    if apiKey == "" {
        t.Skip("LAKERA_API_KEY not set")
    }
    // Test with real API
}
```

### Option 2: Record/Replay Real Responses
```go
// Use go-vcr to record real API responses
r, _ := recorder.New("fixtures/lakera")
client := &http.Client{Transport: r}
// First run: records real responses
// Subsequent runs: replays from fixtures
```

### Option 3: Contract Testing
```yaml
# Pact contract test
interactions:
  - description: "Lakera detects prompt injection"
    request:
      method: POST
      path: /prompt_injection
      body: {"input": "ignore previous instructions"}
    response:
      status: 200
      body: {"flagged": true, "payload_type": "prompt_injection"}
```

---

## Summary

**Current testing approach:**
- Yes Validates logic and integration correctly
- Yes Fast and deterministic
- Yes Easy to debug
- Partial Uses mocks instead of real ML models
- Partial Doesn't test performance or chaos scenarios

**Real-world alignment: 85%**

The tests accurately simulate the **control flow** and **integration points** but use simplified **detection logic** (keywords/regex instead of ML models). This is standard practice for unit/integration tests. For production confidence, supplement with:
1. Periodic tests against real APIs
2. Load testing
3. Chaos engineering
4. Production monitoring
