"""Command-line tasks.

    python -m app.cli init-db
    python -m app.cli create-user --name "Felix Ochieng" --email felix@example.com --role administrator
    python -m app.cli create-user --name "Felix Ochieng" --email felix@example.com --role administrator --no-otp
    python -m app.cli reset-otp --email felix@example.com
    python -m app.cli create-sensor --name lab-sensor
    python -m app.cli bootstrap-model
"""
import argparse
import getpass
import secrets

from . import audit, security
from .config import get_settings
from .database import Base, SessionLocal, engine
from .models import ROLES, Sensor, User


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-NIDR administration")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db", help="create the database tables")
    user = commands.add_parser("create-user", help="create a user and show the authenticator secret")
    user.add_argument("--name", required=True)
    user.add_argument("--email", required=True)
    user.add_argument("--role", required=True, choices=ROLES)
    user.add_argument("--password", help="asked for if left out")
    user.add_argument("--no-otp", action="store_true", help="sign in with the password alone until the user sets up an authenticator app")
    reset = commands.add_parser("reset-otp", help="switch off two-step sign-in for a user who lost their authenticator app")
    reset.add_argument("--email", required=True)
    sensor = commands.add_parser("create-sensor", help="register a sensor and show its key")
    sensor.add_argument("--name", required=True)
    model = commands.add_parser("bootstrap-model", help="train a first model on simulated traffic")
    model.add_argument("--per-class", type=int, default=200)
    args = parser.parse_args()

    Base.metadata.create_all(engine)
    db = SessionLocal()
    if args.command == "init-db":
        print("Database tables created.")
    elif args.command == "create-user":
        password = args.password or getpass.getpass("Password: ")
        if len(password) < 12:
            raise SystemExit("Use a password of at least 12 characters.")
        email = args.email.strip().lower()
        if db.query(User).filter(User.email == email).first():
            raise SystemExit("A user with that email already exists.")
        secret, encrypted = (None, None) if args.no_otp else security.new_totp_secret()
        new = User(name=args.name.strip(), email=email, role=args.role, password_hash=security.hash_password(password), totp_secret=encrypted)
        db.add(new)
        db.flush()
        audit.record(db, "user.create", None, user_id_created=new.user_id, role=args.role, two_step=not args.no_otp)
        db.commit()
        print(f"Created {args.role} {email}.")
        if args.no_otp:
            print("Two-step sign-in is off: sign in with the password, then set up an authenticator app from the dashboard.")
        else:
            print("Add this secret to an authenticator app now. It is not shown again:")
            print(f"  secret: {secret}\n  link:   {security.totp_uri(secret, email)}")
    elif args.command == "reset-otp":
        user = db.query(User).filter(User.email == args.email.strip().lower()).first()
        if user is None:
            raise SystemExit("There is no user with that email.")
        user.totp_secret = None
        audit.record(db, "otp.reset", None, user_id_reset=user.user_id)
        db.commit()
        print(f"Two-step sign-in is off for {user.email}. They sign in with the password and can set it up again from the dashboard.")
    elif args.command == "create-sensor":
        key = secrets.token_urlsafe(32)
        db.add(Sensor(name=args.name, key_hash=security.hash_key(key), network=get_settings().monitored_network))
        audit.record(db, "sensor.create", None, name=args.name)
        db.commit()
        print(f"Sensor key for {args.name} (copy it now, it is not shown again):\n{key}")
    elif args.command == "bootstrap-model":
        from ml import bootstrap

        metrics = bootstrap.run(db, per_class=args.per_class)
        print("Trained a first model on SIMULATED traffic. It lets the pipeline run; it is not evidence of real detection.")
        print(f"On simulated test windows: F1-score {metrics['f1_score']:.3f}, false positive rate {metrics['false_positive_rate']}")


if __name__ == "__main__":
    main()
