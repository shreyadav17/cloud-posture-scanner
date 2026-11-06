
import logging

import boto3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .config import DEMO_MODE, CORS_ORIGINS, AWS_REGION, DYNAMODB_TABLE
from .demo import demo_data
from .scanner import run_scan, save_scan


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI(
    title="Cloud Posture Scanner API",
    version="1.1.0",
    description="AWS resource inventory and CIS-inspired security checks"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


_state = (
    demo_data()
    if DEMO_MODE
    else {
        "generated_at": None,
        "instances": [],
        "buckets": [],
        "cis_results": []
    }
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "mode": "demo" if DEMO_MODE else "live"
    }


@app.get("/instances")
def instances():
    return _state["instances"]


@app.get("/buckets")
def buckets():
    return _state["buckets"]


@app.get("/cis-results")
def cis_results():
    return _state["cis_results"]


@app.get("/summary")
def summary():
    checks = _state["cis_results"]

    return {
        "instances": len(_state["instances"]),
        "buckets": len(_state["buckets"]),
        "passed": sum(
            c["status"] == "PASS" for c in checks
        ),
        "failed": sum(
            c["status"] == "FAIL" for c in checks
        ),
        "errors": sum(
            c["status"] in ("ERROR", "UNKNOWN")
            for c in checks
        ),
        "generated_at": _state["generated_at"]
    }


@app.get("/scan-history")
def scan_history():
    if DEMO_MODE:
        return {
            "history": [],
            "message": "Scan history is available in live mode."
        }

    if not DYNAMODB_TABLE:
        raise HTTPException(
            status_code=503,
            detail="DynamoDB table is not configured"
        )

    try:
        dynamodb = boto3.resource(
            "dynamodb",
            region_name=AWS_REGION
        )

        table = dynamodb.Table(DYNAMODB_TABLE)

        response = table.scan(
            Limit=50,
            ProjectionExpression=(
                "#sid, generated_at, instances, buckets, cis_results"
            ),
            ExpressionAttributeNames={
                "#sid": "scan_id"
            }
        )

        items = response.get("Items", [])

        history = []

        for item in items:
            checks = item.get("cis_results", [])

            passed = sum(
                c.get("status") == "PASS" for c in checks
            )

            failed = sum(
                c.get("status") == "FAIL" for c in checks
            )

            errors = sum(
                c.get("status") in ("ERROR", "UNKNOWN")
                for c in checks
            )

            evaluated = passed + failed

            score = (
                round((passed / evaluated) * 100)
                if evaluated else None
            )

            history.append({
                "scan_id": item.get("scan_id"),
                "generated_at": item.get("generated_at"),
                "instances": len(item.get("instances", [])),
                "buckets": len(item.get("buckets", [])),
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "security_score": score
            })

        history.sort(
            key=lambda x: x.get("generated_at") or "",
            reverse=True
        )

        return {
            "history": history,
            "count": len(history)
        }

    except Exception as e:
        logger.exception("Scan history retrieval failed")

        raise HTTPException(
            status_code=500,
            detail=f"Unable to retrieve scan history: {_safe_error(e)}"
        )


@app.post("/scan")
def scan():
    global _state

    if DEMO_MODE:
        _state = demo_data()

        return {
            "message": "Demo scan refreshed",
            "stored": False,
            "data": _state
        }

    try:
        scan_data = run_scan()

    except Exception as e:
        logger.exception("AWS scan failed")

        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {_safe_error(e)}"
        )

    _state = scan_data

    try:
        stored = save_scan(scan_data)

        if stored:
            message = "Live scan completed and results stored in DynamoDB"
            storage_error = None
        else:
            message = "Live scan completed but results were not stored"
            storage_error = "DynamoDB storage was not configured"

    except Exception as e:
        logger.exception("DynamoDB storage failed")

        stored = False
        message = "Live scan completed but DynamoDB storage failed"
        storage_error = _safe_error(e)

    return {
        "message": message,
        "stored": stored,
        "storage_error": storage_error,
        "data": scan_data
    }


def _safe_error(error):
    return str(error)[:500]
