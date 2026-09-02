# KYA Phase 1K — Production Datastore Evaluation

## Status: EVALUATION COMPLETE — SQLite is sufficient for current workload

**Date:** September 1, 2026
**Decision:** Do NOT migrate to PostgreSQL yet.

---

## Current SQLite Usage

| Table | Location | Write Pattern | Read Pattern | Concurrency |
|-------|----------|---------------|--------------|-------------|
| `execution_claims` | execution_claims.db | INSERT + UPDATE (reserve/finalize) | SELECT by jti | Low (per-request) |
| `finalization_outbox` | execution_claims.db | INSERT + DELETE (outbox/replay) | SELECT on startup | Low (startup only) |
| `audit_entries` | audit_trail.db | INSERT + UPDATE | SELECT by id/jti | Low (per-request) |
| `transaction_history` | baselines.db | INSERT + DELETE (prune) | SELECT by agent_id | Low (per-request) |
| `reconciliation_log` | execution_claims.db | INSERT | SELECT by audit_id | Very low |

**Total write volume estimate:** ~10-50 writes/second at peak (demo workload)

---

## SQLite Strengths for Current Workload

1. **Zero infrastructure:** No separate database server to manage
2. **ACID transactions:** WAL mode provides concurrent reads without blocking writes
3. **Durability:** Synchronous mode (default) ensures writes hit disk
4. **Simplicity:** Single-file backup, no connection pooling needed
5. **Performance:** Sub-millisecond for the access patterns above

## SQLite Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Single-writer | Write contention under high load | WAL mode allows concurrent reads |
| No network access | Cannot share across machines | Acceptable for single-server deployment |
| No connection pooling | Limited by process memory | Fine for <100 concurrent connections |
| No row-level locking | Table-level locks on write | Low write volume makes this acceptable |
| No replication | No failover | Use filesystem-level backups |

## When PostgreSQL Would Be Needed

| Trigger | Threshold | Current Status |
|---------|-----------|----------------|
| Write throughput | >1000 writes/sec sustained | ❌ Not reached |
| Concurrent workers | >4 uvicorn workers | ❌ Currently 1 worker |
| Cross-machine access | Multi-server deployment | ❌ Single server |
| Audit compliance | Requires row-level security | ⚠️ Future consideration |
| Query complexity | JOINs across tables | ❌ Simple queries |
| Backup requirements | Point-in-time recovery | ⚠️ Future consideration |

## Migration Path (When Needed)

### Step 1: Add PostgreSQL adapter
```python
# backend/datastore.py
class DataStore(ABC):
    @abstractmethod
    def execute(self, sql, params): ...
    @abstractmethod
    def fetchone(self, sql, params): ...
    @abstractmethod
    def fetchall(self, sql, params): ...
```

### Step 2: Implement PostgreSQL adapter
```python
class PostgreSQLDataStore(DataStore):
    def __init__(self, dsn):
        self.pool = psycopg2.pool.ThreadedConnectionPool(1, 10, dsn)
```

### Step 3: Migrate tables
```sql
-- execution_claims
CREATE TABLE execution_claims (
    jti TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'RESERVED',
    audit_id TEXT,
    order_id TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- audit_entries (JSONB for flexibility)
CREATE TABLE audit_entries (
    id TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_audit_jti ON audit_entries ((data->>'jti'));
```

### Step 4: Update connection management
- Replace `sqlite3.connect()` with connection pool
- Update `PRAGMA` statements to PostgreSQL equivalents
- Test all queries against PostgreSQL

---

## Recommendation

**Keep SQLite for now.** The current workload is:
- Low write volume (<50/sec)
- Single-server deployment
- Simple query patterns
- No cross-machine access needed

**Revisit when:**
- Multiple uvicorn workers are deployed
- Write throughput exceeds 1000/sec
- Multi-server deployment is planned
- Audit compliance requires row-level security

The provider-neutral interfaces (rate_limiter.py, payment_provider.py) already demonstrate the pattern for swapping backends. The same approach applies to the datastore when migration is needed.
