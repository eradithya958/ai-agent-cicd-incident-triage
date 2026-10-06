"""
Fleet Telemetry Gateway Ingestion Service
"""
import httpx

from app.models import IngestResponse, TelemetryBatch


class TelemetryIngestService:
    def __init__(self, upstream_gateway_url: str = "http://mock-sensor.internal:8080"):
        self.upstream_gateway_url = upstream_gateway_url

    async def ingest_batch(self, batch: TelemetryBatch) -> IngestResponse:
        # Validate batch non-emptiness
        if not batch.readings:
            raise ValueError("Telemetry batch cannot be empty")

        # Forward to upstream aggregator mock
        upstream_ack = False
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.post(
                    f"{self.upstream_gateway_url}/api/v1/aggregate",
                    json={"vin": batch.vehicle_vin, "count": len(batch.readings)},
                )
                upstream_ack = (res.status_code == 200)
        except (httpx.ConnectTimeout, httpx.NetworkError):
            # In test environments, mock connection timeout may occur
            upstream_ack = False

        return IngestResponse(
            status="SUCCESS",
            processed_count=len(batch.readings),
            vehicle_vin=batch.vehicle_vin,
            upstream_ack=upstream_ack,
        )
