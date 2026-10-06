"""
Fleet Telemetry Gateway Data Models
"""

from pydantic import BaseModel, Field, field_validator


class SensorReading(BaseModel):
    sensor_id: str = Field(..., description="Unique vehicle sensor identifier")
    timestamp_epoch_ms: int = Field(..., description="Epoch timestamp in milliseconds")
    speed_kmh: float = Field(..., ge=0.0, le=250.0, description="Vehicle velocity in km/h")
    battery_level_pct: float = Field(..., ge=0.0, le=100.0, description="Battery state of charge")
    latitude: float | None = Field(None, ge=-90.0, le=90.0)
    longitude: float | None = Field(None, ge=-180.0, le=180.0)

    @field_validator("speed_kmh")
    @classmethod
    def validate_speed(cls, v: float) -> float:
        if v < 0:
            raise ValueError("Speed cannot be negative")
        return round(v, 2)


class TelemetryBatch(BaseModel):
    vehicle_vin: str = Field(..., min_length=17, max_length=17, description="17-char VIN")
    readings: list[SensorReading] = Field(..., min_length=1)
    client_version: str = "v1.4.0"


class IngestResponse(BaseModel):
    status: str
    processed_count: int
    vehicle_vin: str
    upstream_ack: bool
