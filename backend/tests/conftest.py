import os
import random
import tempfile

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["MODEL_DIR"] = tempfile.mkdtemp(prefix="ainidr-models-")
os.environ["SECRET_KEY"] = "test-secret-key-test-secret-key-0123456789"

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import security  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.engine import simulate  # noqa: E402
from app.limits import limiter  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Sensor, User  # noqa: E402
from app.response.firewall import Firewall, FirewallError  # noqa: E402
from ml import bootstrap, common  # noqa: E402

PASSWORD = "correct-horse-battery-staple"
SENSOR_KEY = "test-sensor-key"
ATTACKER, TARGET = "192.168.56.10", "192.168.56.20"


class FakeFirewall(Firewall):
    def __init__(self) -> None:
        self.blocked: dict[str, int] = {}
        self.fail = False

    def block(self, ip: str, minutes: int) -> None:
        if self.fail:
            raise FirewallError("host could not be reached")
        self.blocked[ip] = minutes

    def unblock(self, ip: str) -> None:
        self.blocked.pop(ip, None)


@pytest.fixture(scope="session")
def bundles():
    """Train the simulated-traffic models once for the whole test run."""
    X, labels = bootstrap.simulated_windows(per_class=120)
    classifier, metrics = common.train_classifier(X, labels, "random_forest", "test")
    return classifier, metrics, common.train_anomaly(X[[label == "normal" for label in labels]], "test")


@pytest.fixture
def db(bundles):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    secrets = {}
    for name, role in (("Vera", "viewer"), ("Ann", "analyst"), ("Adam", "administrator")):
        secret, encrypted = security.new_totp_secret()
        secrets[role] = secret
        session.add(User(name=name, email=f"{name.lower()}@example.com", role=role,
                         password_hash=security.hash_password(PASSWORD), totp_secret=encrypted))
    session.add(Sensor(name="lab", key_hash=security.hash_key(SENSOR_KEY), network="192.168.56.0/24"))
    session.commit()
    common.save_and_register(session, bundles[0], bundles[1])
    common.save_and_register(session, bundles[2])
    session.totp = secrets
    yield session
    session.close()


@pytest.fixture
def firewall():
    return FakeFirewall()


@pytest.fixture
def client(db, firewall):
    limiter.hits.clear()  # every test starts with a fresh request limit, as a new minute would
    with TestClient(create_app(firewall)) as test_client:
        yield test_client


@pytest.fixture
def token(client, db):
    def _token(role: str) -> dict:
        name = {"viewer": "vera", "analyst": "ann", "administrator": "adam"}[role]
        reply = client.post("/api/v1/auth/login", json={"email": f"{name}@example.com", "password": PASSWORD,
                                                        "code": pyotp.TOTP(db.totp[role]).now()})
        assert reply.status_code == 200, reply.text
        return {"Authorization": f"Bearer {reply.json()['access_token']}"}

    return _token


def traffic(kind: str, source: str = ATTACKER, start: float = 2_000_000.0, seconds: float = 45, seed: int = 3) -> list[dict]:
    return simulate.GENERATORS[kind](source, TARGET, start, seconds, random.Random(seed))


@pytest.fixture
def send(client):
    def _send(records: list[dict]):
        reply = client.post("/api/v1/ingest/connections", json={"records": records}, headers={"X-Sensor-Key": SENSOR_KEY})
        assert reply.status_code == 200, reply.text
        return reply.json()

    return _send
