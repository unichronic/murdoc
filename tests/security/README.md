# Security Framework Testing

This directory contains tests for the Murdoc security framework (OPA + Lakera + Presidio).

## Structure

```text
tests/security/
-  opa_test.go
-  presidio_test.go
-  lakera_test.go
-  integration_test.go

tests/fixtures/policies/
-  allow_all.rego
-  block_sensitive.rego
-  main.rego
```

## Running Tests

### Unit Tests
```bash
cd tests/security
go test ./... -v

# Run specific layer
go test -run TestOPAMiddleware -v
go test -run TestLakeraMiddleware -v
go test -run TestPresidioMiddleware -v
```

### Integration Tests
```bash
cd tests/security
go test -run TestSecurityPipeline_FullFlow -v

# Or skip with short flag
go test ./... -short
```

## Test Scenarios

| Test | Input | Expected | Validates |
|------|-------|----------|-----------|
| Clean request | "What is 2+2?" | Pass Pass | No false positives |
| Prompt injection | "Ignore previous instructions" | Block Block | Lakera detection |
| SSN | "My SSN is 123-45-6789" | Block Block | OPA policy |
| Credit card | "Card: 4111-1111-1111-1111" | Block Block | OPA policy |
| Email | "user@example.com" | Block Block | OPA policy |

## Adding New Tests

1. Create test file in `tests/security/`
2. Add test policy in `tests/fixtures/policies/` if needed
3. Update this README with new test scenarios
