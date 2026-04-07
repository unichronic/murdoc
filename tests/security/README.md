# Security Framework Testing

This directory contains tests for the Bifrost security framework (OPA + Lakera + Presidio).

## Structure

```
tests/security/
├── opa_test.go           # OPA middleware unit tests
├── presidio_test.go      # Presidio PII detection tests
├── lakera_test.go        # Lakera prompt injection tests
└── integration_test.go   # Full pipeline integration tests

testdata/policies/
├── allow_all.rego        # Test policy: allow everything
├── block_sensitive.rego  # Test policy: block PII patterns
└── main.rego            # Integration test policy

scripts/
└── test_security.sh      # Manual E2E testing script
```

## Running Tests

### Unit Tests
```bash
# Run all security tests
go test ./tests/security/... -v

# Run specific layer
go test ./tests/security/opa_test.go -v
go test ./tests/security/lakera_test.go -v
go test ./tests/security/presidio_test.go -v
```

### Integration Tests
```bash
# Run with integration tag
go test ./tests/security/integration_test.go -v -tags=integration

# Or skip with short flag
go test ./tests/security/... -short
```

### Manual E2E Tests
```bash
# Start Bifrost with security plugins enabled
make dev

# In another terminal, run test script
./scripts/test_security.sh
```

## Test Scenarios

| Test | Input | Expected | Validates |
|------|-------|----------|-----------|
| Clean request | "What is 2+2?" | ✓ Pass | No false positives |
| Prompt injection | "Ignore previous instructions" | ✗ Block | Lakera detection |
| SSN | "My SSN is 123-45-6789" | ✗ Block | OPA policy |
| Credit card | "Card: 4111-1111-1111-1111" | ✗ Block | OPA policy |
| Email | "user@example.com" | ✗ Block | OPA policy |

## Adding New Tests

1. Create test file in `tests/security/`
2. Add test policy in `testdata/policies/` if needed
3. Update this README with new test scenarios
