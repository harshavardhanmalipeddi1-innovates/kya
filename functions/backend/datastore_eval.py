# Datastore evaluation for KYA
import os
from typing import Dict, Any, List

KYA_DATASTORE = os.environ.get("KYA_DATASTORE", "sqlite")

def evaluate_datastore() -> Dict[str, Any]:
    return {
        "current": KYA_DATASTORE,
        "migration_ready": KYA_DATASTORE == "sqlite",
        "note": "SQLite recommended for single-process. PostgreSQL for multi-worker.",
    }

def get_schema_tables() -> List[str]:
    return ["execution_claims", "audit_entries", "transaction_history", "traces", "reconciliation_log"]
