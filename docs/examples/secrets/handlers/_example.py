"""External example handlers. Python and their tools own the secret material they receive."""
import getpass
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile


def fail(message):
    raise RuntimeError(message)


def ask(instruction):
    if os.environ.get("BROIL_ROTATION_NON_INTERACTIVE") == "1":
        fail("This example requires private-terminal proof.")
    with open("/dev/tty", "r+") as terminal:
        terminal.write(instruction + "\nConfirmed (yes/no): ")
        terminal.flush()
        if terminal.readline().rstrip("\r\n") != "yes":
            fail("External proof was not confirmed.")


def tool(argv, value=None, env=None):
    result = subprocess.run(argv, input=value, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env, timeout=60)
    if result.returncode:
        fail("External tool failed; verify the service before retrying.")
    return result.stdout


def db_names(rotation_id):
    user = os.environ.get("ROTATION_DB_USER", "app")
    if len(user) > 39 or not re.fullmatch(r"[a-z_][a-z0-9_]*", user):
        fail("DB user must be a lowercase SQL identifier of at most 39 ASCII bytes.")
    role = user + "_r" + rotation_id
    hosts = os.environ.get("ROTATION_DB_HOSTS", os.environ.get(
        "ROTATION_DB_HOST", "db-primary.example.test db-secondary.example.test")).split()
    if not hosts:
        fail("Configure at least one DB host.")
    return user, role, hosts


def sql(host, user, statement, password=None):
    env = dict(os.environ)
    if password is not None:
        env["PGPASSWORD"] = password.decode("utf-8")
    return tool(["psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
                 "-h", host, "-U", user, "-d", os.environ.get("ROTATION_DB_NAME", "postgres")],
                statement.encode("utf-8"), env)


def db(profile_state, verb, value, rotation_id):
    user, role, hosts = db_names(rotation_id)
    password = value.decode("utf-8").replace("'", "''")
    if profile_state == "CREATED" and verb == "action":
        for host in hosts:
            exists = sql(host, "postgres", f"SELECT 1 FROM pg_roles WHERE rolname='{role}';").strip()
            if exists != b"1":
                sql(host, "postgres", f"CREATE ROLE {role} LOGIN;")
            sql(host, "postgres", f"SET standard_conforming_strings=on; ALTER ROLE {role} PASSWORD '{password}'; GRANT {user} TO {role};")
    elif profile_state == "CREATED" and verb == "verify":
        for host in hosts:
            sql(host, role, "SELECT 1;", value)
    elif verb == "rollback" and profile_state == "CREATED":
        for host in hosts:
            sql(host, "postgres", f"DROP ROLE IF EXISTS {role};")
    elif verb == "rollback":
        ask(f"Undo {profile_state}: consumers must use the restored old value and original DB role {user} on every host. Do not edit the Broil store.")
    elif profile_state == "TRANSITION_READY":
        for host in hosts:
            sql(host, role, "SELECT 1;", value)
        ask(f"Verify old access remains usable on {', '.join(hosts)} and configure the next deployment to use temporary role {role} with the candidate.")
    elif profile_state == "OLD_REVOKED" and verb == "action":
        for host in hosts:
            sql(host, "postgres", f"SET standard_conforming_strings=on; ALTER ROLE {user} PASSWORD '{password}';")
        ask(f"Redeploy consumers back to original role {user} with the current value; prove all are healthy before removing temporary role {role}.")
        for host in hosts:
            sql(host, "postgres", f"DROP ROLE IF EXISTS {role};")
    elif profile_state == "OLD_REVOKED":
        for host in hosts:
            sql(host, user, "SELECT 1;", value)
            if sql(host, "postgres", f"SELECT 1 FROM pg_roles WHERE rolname='{role}';").strip() == b"1":
                fail("Temporary role remains live.")
        ask("Prove the OLD password is rejected on every configured host.")
    else:
        ask(f"Verify {profile_state}: every consumer and DB connection works with the current credential on all hosts.")


def ssh_directory(rotation_id):
    parent = Path("/dev/shm")
    if not parent.is_dir() or not os.access(parent, os.W_OK):
        parent = Path(tempfile.gettempdir())
        print("SSH handler uses persistent temporary storage; crashes may leave private material.", file=sys.stderr)
    directory = parent / ("broil-rotation-ssh-" + rotation_id)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail("Unsafe SSH handler directory.")
    return directory


def install_key(directory, value):
    path = directory / "new_key"
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            fail("Unsafe SSH handler key file.")
    fd, temporary = tempfile.mkstemp(prefix=".key-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(value)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def ssh(state, verb, value, rotation_id):
    directory = ssh_directory(rotation_id)
    path = install_key(directory, value) if value else directory / "new_key"
    if value:
        public = tool(["ssh-keygen", "-y", "-f", str(path)])
    else:
        public = b""
    if state == "CREATED":
        if verb != "rollback" and not public:
            fail("Use --generator ssh-ed25519 with this example.")
    elif verb == "rollback":
        ask(f"Undo {state}: remove the candidate public key and restore consumers' old access. Broil owns store restoration.")
    elif state == "TRANSITION_READY":
        if verb == "action":
            print(public.decode("ascii").rstrip(), file=sys.stderr)
            ask("Install this PUBLIC key on every target alongside old access.")
        else:
            target = os.environ.get("ROTATION_SSH_TARGET")
            if not target or target.startswith("-"):
                fail("Configure ROTATION_SSH_TARGET for a real SSH verification.")
            tool(["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", str(path), target, "true"])
            ask("Confirm both old and new SSH access work on every target.")
    elif state == "OLD_REVOKED":
        ask("Remove the OLD public key on every target and prove old access is rejected.")
    else:
        ask(f"Verify {state}: actual consumers' SSH operations work with the new key.")
    if (state == "VERIFIED" and verb == "verify") or (state == "CREATED" and verb == "rollback"):
        for name in ("new_key", "new_key.pub"):
            try:
                (directory / name).unlink()
            except FileNotFoundError:
                pass
        directory.rmdir()
    return str(directory)


def manual(profile, state, verb):
    if verb == "rollback":
        ask(f"Undo {state}: remove the candidate external credential and restore consumers using Broil's restored value. Provider-assigned orphan keys may require dashboard inspection.")
    elif state == "CREATED" and verb == "action":
        return
    elif state == "CREATED":
        ask(f"Test the new {profile} against its real provider/receiver and confirm success.")
    elif state == "TRANSITION_READY":
        ask(f"Configure the {profile} provider/receiver to accept BOTH credentials; prove both work.")
    elif state == "DEPLOYED":
        ask("Prove every deployed consumer uses the new credential successfully.")
    elif state == "OLD_REVOKED":
        ask("Revoke/remove the OLD credential and prove its requests are rejected.")
    elif state == "VERIFIED":
        ask("Run an end-to-end smoke test of all affected integrations.")


def main(profile):
    try:
        if sys.argv[1:] == ["capabilities"]:
            print('{"recreate":[]}')
            return
        if len(sys.argv) != 3 or sys.argv[1] not in ("CREATED", "TRANSITION_READY", "DEPLOYED", "OLD_REVOKED", "VERIFIED") or sys.argv[2] not in ("action", "verify", "rollback"):
            fail("Unsupported callback; STORE_UPDATED belongs to Broil.")
        state, verb = sys.argv[1:]
        rotation_id = os.environ["BROIL_ROTATION_ID"]
        if not re.fullmatch(r"[0-9]{14}[0-9a-f]{8}", rotation_id):
            fail("Invalid recorded rotation ID.")
        if profile == "db-password":
            db_names(rotation_id)
        value = sys.stdin.buffer.read(1024 * 1024 + 1)
        supplied = bool(value)
        if not value and state == "CREATED" and verb == "action":
            if profile == "api-key":
                ask("Create a provider-assigned key. If interrupted before Broil persists it, inspect the provider dashboard for orphan keys.")
                value = getpass.getpass("Provider key: ").encode("utf-8")
            elif profile == "ssh-key":
                fail("Use --generator ssh-ed25519 with the SSH example.")
            else:
                value = secrets.token_hex(32).encode("ascii")
        if len(value) > 1024 * 1024 or b"\0" in value or (not value and not (state == "CREATED" and verb == "rollback")):
            fail("Invalid candidate input.")
        value.decode("utf-8")
        note = None
        if profile == "db-password":
            db(state, verb, value, rotation_id)
        elif profile == "ssh-key":
            note = ssh(state, verb, value, rotation_id)
        else:
            manual(profile, state, verb)
        if state == "CREATED" and verb == "action":
            if not supplied:
                sys.stdout.buffer.write(b"BROIL_ROTATION_VALUE_BYTES=" + str(len(value)).encode("ascii") + b"\n" + value)
            if note is not None:
                sys.stdout.buffer.write(("\n" if not supplied else "").encode() + b"BROIL_ROTATION_NOTE=" + note.encode() + b"\n")
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Example handler failed; inspect the external service and rotation status before retrying.", file=sys.stderr)
        sys.exit(1)
