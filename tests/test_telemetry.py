"""
Telemetry Model and Logic Tests
"""
import pytest

from app.models import SensorReading, TelemetryBatch


def test_sensor_reading_validation_positive():
    reading = SensorReading(
        sensor_id="RADAR_REAR_02",
        timestamp_epoch_ms=1775220000000,
        speed_kmh=45.238,
        battery_level_pct=92.5,
    )
    assert reading.speed_kmh == 45.24
    assert reading.sensor_id == "RADAR_REAR_02"


def test_sensor_reading_negative_speed():
    with pytest.raises(ValueError):
        SensorReading(
            sensor_id="RADAR_REAR_02",
            timestamp_epoch_ms=1775220000000,
            speed_kmh=-10.0,
            battery_level_pct=92.5,
        )


def test_invalid_vin_length():
    with pytest.raises(ValueError):
        TelemetryBatch(
            vehicle_vin="TOO_SHORT",
            readings=[
                SensorReading(
                    sensor_id="RADAR_01",
                    timestamp_epoch_ms=1775220000000,
                    speed_kmh=10.0,
                    battery_level_pct=50.0,
                )
            ]
        )
