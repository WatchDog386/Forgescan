from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..events import hub
from ..limits import limiter
from ..models import Sensor

router = APIRouter(prefix="/ingest", tags=["sensor"])


class ConnectionsIn(BaseModel):
    records: list[dict] = Field(max_length=20000, description="Lines of Zeek's conn.log, as JSON objects")


def sensor_from_key(x_sensor_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> Sensor:
    """A sensor key may only submit records (FR-11)."""
    sensor = db.query(Sensor).filter(Sensor.key_hash == security.hash_key(x_sensor_key)).first() if x_sensor_key else None
    if sensor is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The sensor key is missing or wrong.")
    limiter.check(f"sensor:{sensor.sensor_id}", 600)
    return sensor


@router.post("/connections")
async def connections(body: ConnectionsIn, request: Request, sensor: Sensor = Depends(sensor_from_key), db: Session = Depends(get_db)):
    result = request.app.state.pipeline.process(db, sensor, body.records)
    for event in result["events"]:
        await hub.broadcast(event)
    return {"received": result["received"], "skipped": result["skipped"], "windows": result["windows"],
            "alerts": sum(1 for e in result["events"] if e["type"] == "alert")}
