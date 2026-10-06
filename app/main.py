"""
FastAPI Application Entrypoint for Fleet Telemetry Gateway
"""
from fastapi import FastAPI, HTTPException

from app.models import IngestResponse, TelemetryBatch
from app.service import TelemetryIngestService

app = FastAPI(
    title="Fleet Telemetry Gateway",
    version="1.0.0",
    description="Microservice for ingesting autonomous vehicle telemetry data."
)

service = TelemetryIngestService()


@app.get("/healthz")
async def healthz():
    return {"status": "HEALTHY", "version": "1.0.0"}


@app.post("/api/v1/telemetry", response_model=IngestResponse)
async def ingest_telemetry(batch: TelemetryBatch):
    try:
        result = await service.ingest_batch(batch)
        return result
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
