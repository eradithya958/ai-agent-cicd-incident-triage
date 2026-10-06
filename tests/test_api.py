"""
Unit Tests for Fleet Telemetry Gateway API
"""
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_valid_telemetry_batch_ingest():
    payload = {
        "vehicle_vin": "VOLVO123456789012",
        "readings": [
            {
                "sensor_id": "LIDAR_FRONT_01",
                "timestamp_epoch_ms": 1775220000000,
                "speed_kmh": 65.5,
                "battery_level_pct": 84.0,
                "latitude": 57.7089,
                "longitude": 11.9746
            }
        ]
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/telemetry", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["processed_count"] == 1
    assert data["vehicle_vin"] == "VOLVO123456789012"
