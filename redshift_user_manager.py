#!/usr/bin/env python3
"""
Interactive Redshift user manager.

Features
--------
- Loads Redshift connection settings from a .env file.
- Curses-based navigation with arrow keys and checkboxes.
- Create users (auto-generates a strong password when left empty).
- Reset passwords for existing users.
- Grant/revoke read-only or read/write privileges per database/schema.
- Delete users.

The interface and code are intentionally kept in English to match the request.
"""
from __future__ import annotations

import curses
import os
import re
import secrets
import string
import sys
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional runtime dependency
    load_dotenv = None

try:
    import psycopg2
    from psycopg2 import sql
except ImportError:  # pragma: no cover - optional runtime dependency
    psycopg2 = None
    sql = None


ENV_KEYS = ["REDSHIFT_HOST", "REDSHIFT_PORT", "REDSHIFT_USER", "REDSHIFT_PASSWORD", "REDSHIFT_DATABASE"]
HEADER_ART = [
    "▗▄▄▖     ▗▖ ▗▖    ▗▖  ▗▖",
    "▐▌ ▐▌    ▐▌ ▐▌    ▐▛▚▞▜▌",
    "▐▛▀▚▖    ▐▌ ▐▌    ▐▌  ▐▌",
    "▐▌ ▐▌    ▝▚▄▞▘    ▐▌  ▐▌",
    "                        ",
]

# Colors will be initialized at runtime; defaults prevent crashes if colors are unavailable.
COLOR_HEADER = curses.A_BOLD
COLOR_HIGHLIGHT = curses.A_REVERSE
COLOR_DIM = curses.A_DIM
COLOR_NORMAL = curses.A_NORMAL


@dataclass
class Settings:
    host: str
    port: int
    user: str
    password: str
    database: str


@dataclass
class SchemaPrivilege:
    database: str
    schema: str
    read: bool = False
    write: bool = False

    def label(self) -> str:
        flags = f"[R:{'x' if self.read else ' '}] [W:{'x' if self.write else ' '}]"
        return f"{flags} {self.database}.{self.schema}"

    def ensure_write_implies_read(self) -> None:
        if self.write and not self.read:
            self.read = True


def ensure_dependencies() -> None:
    if psycopg2 is None or sql is None:
        sys.exit("psycopg2 is required. Install with: pip install psycopg2-binary")


def init_colors() -> None:
    """Initialize color pairs with safe fallbacks."""
    global COLOR_HEADER, COLOR_HIGHLIGHT, COLOR_DIM, COLOR_NORMAL
    COLOR_HEADER = curses.A_BOLD
    COLOR_HIGHLIGHT = curses.A_REVERSE
    COLOR_DIM = curses.A_DIM
    COLOR_NORMAL = curses.A_NORMAL
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    try:
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        COLOR_HEADER = curses.color_pair(1) | curses.A_BOLD
        COLOR_HIGHLIGHT = curses.color_pair(2) | curses.A_BOLD
        COLOR_DIM = curses.color_pair(3) | curses.A_DIM
        COLOR_NORMAL = curses.color_pair(3)
    except Exception:
        # Keep defaults if color initialization fails.
        pass


def load_settings() -> Settings:
    if load_dotenv:
        load_dotenv()
    missing = [key for key in ENV_KEYS if not os.getenv(key)]
    if missing:
        sys.exit(f"Missing environment variables: {', '.join(missing)} (check your .env file)")
    try:
        port = int(os.getenv("REDSHIFT_PORT", "5439"))
    except ValueError:
        sys.exit("REDSHIFT_PORT must be an integer")
    return Settings(
        host=os.getenv("REDSHIFT_HOST", ""),
        port=port,
        user=os.getenv("REDSHIFT_USER", ""),
        password=os.getenv("REDSHIFT_PASSWORD", ""),
        database=os.getenv("REDSHIFT_DATABASE", ""),
    )


def validate_username(username: str) -> Optional[str]:
    if not username:
        return "Username is required"
    if not re.match(r"^[A-Za-z][A-Za-z0-9_-]{1,127}$", username):
        return "Username must start with a letter and use letters, numbers, _ or -"
    return None


def generate_password(length: int = 24) -> str:
    symbols = "!@#$%^&*()-_=+[]{}:.?/|"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in symbols for c in pwd)
        ):
            return pwd


@contextmanager
def db_connection(settings: Settings, database: Optional[str] = None):
    conn = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        user=settings.user,
        password=settings.password,
        dbname=database or settings.database,
    )
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def cursor(conn):
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def list_databases(conn) -> List[str]:
    with cursor(conn) as cur:
        try:
            cur.execute(
                """
                -- Prefer SVV_DATABASES to filter out shared/catalog databases
                SELECT datname
                FROM SVV_DATABASES
                WHERE datistemplate = false
                  AND datallowconn = true
                  AND (datshare_type IS NULL OR datshare_type = '')
                ORDER BY datname
                """
            )
        except Exception:
            cur.connection.rollback()
            # Fallback for clusters without SVV_DATABASES visibility
            cur.execute(
                """
                SELECT datname
                FROM pg_database
                WHERE datistemplate = false
                  AND datallowconn = true
                  AND datname NOT IN ('awsdatacatalog')
                  AND datname NOT LIKE 'pg_%'
                ORDER BY datname
                """
            )
        return [row[0] for row in cur.fetchall()]


def list_schemas(conn) -> List[str]:
    with cursor(conn) as cur:
        cur.execute(
            """
            SELECT nspname
            FROM pg_namespace
            WHERE nspname NOT LIKE 'pg_%'
              AND nspname NOT IN ('information_schema', 'pg_internal')
            ORDER BY nspname
            """
        )
        return [row[0] for row in cur.fetchall()]


def list_users(conn) -> List[str]:
    with cursor(conn) as cur:
        cur.execute(
            """
            SELECT usename
            FROM pg_user
            WHERE usesuper = false
            ORDER BY usename
            """
        )
        return [row[0] for row in cur.fetchall()]


def create_user(conn, username: str, password: str) -> None:
    with cursor(conn) as cur:
        cur.execute(sql.SQL("CREATE USER {} PASSWORD %s").format(sql.Identifier(username)), [password])


def drop_user(conn, username: str) -> None:
    with cursor(conn) as cur:
        cur.execute(sql.SQL("DROP USER {}").format(sql.Identifier(username)))


def reset_password(conn, username: str, password: str) -> None:
    with cursor(conn) as cur:
        cur.execute(sql.SQL("ALTER USER {} PASSWORD %s").format(sql.Identifier(username)), [password])


def fetch_schema_privileges(conn, username: str) -> Dict[str, SchemaPrivilege]:
    with cursor(conn) as cur:
        cur.execute(
            """
            SELECT table_schema,
                   MAX(CASE WHEN privilege_type = 'SELECT' THEN 1 ELSE 0 END) AS can_select,
                   MAX(CASE WHEN privilege_type IN ('INSERT','UPDATE','DELETE') THEN 1 ELSE 0 END) AS can_write
            FROM information_schema.table_privileges
            WHERE grantee = %s
              AND table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
            GROUP BY table_schema
            """,
            [username],
        )
        result: Dict[str, SchemaPrivilege] = {}
        for schema, can_select, can_write in cur.fetchall():
            result[schema] = SchemaPrivilege(
                database=conn.get_dsn_parameters().get("dbname", ""),
                schema=schema,
                read=bool(can_select),
                write=bool(can_write),
            )
        return result


def revoke_privileges(conn, username: str, schema: str) -> None:
    statements = [
        sql.SQL("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {} FROM {}").format(
            sql.Identifier(schema), sql.Identifier(username)
        ),
        sql.SQL("REVOKE USAGE ON SCHEMA {} FROM {}").format(sql.Identifier(schema), sql.Identifier(username)),
        sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE ALL ON TABLES FROM {}").format(
            sql.Identifier(schema), sql.Identifier(username)
        ),
    ]
    with cursor(conn) as cur:
        for statement in statements:
            try:
                cur.execute(statement)
            except Exception:
                # Non-fatal: continue trying the rest to keep state consistent
                conn.rollback()
                conn.commit()


def list_default_privilege_owners(conn) -> List[str]:
    with cursor(conn) as cur:
        cur.execute(
            """
            SELECT DISTINCT u.usename
            FROM pg_default_acl d
            JOIN pg_user u ON u.usesysid = d.defacluser
            WHERE d.defaclobjtype = 'r'  -- tables
            """
        )
        return [row[0] for row in cur.fetchall()]


def revoke_default_privileges(conn, username: str, schema: str, owners: List[str]) -> None:
    for owner in owners:
        try:
            with cursor(conn) as cur:
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR USER {} IN SCHEMA {} REVOKE ALL ON TABLES FROM {}"
                    ).format(sql.Identifier(owner), sql.Identifier(schema), sql.Identifier(username))
                )
        except Exception:
            conn.rollback()
            conn.commit()


def grant_privileges(conn, username: str, schema_priv: SchemaPrivilege) -> None:
    schema_priv.ensure_write_implies_read()
    statements = [
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema_priv.schema), sql.Identifier(username))
    ]
    if schema_priv.read:
        statements.append(
            sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                sql.Identifier(schema_priv.schema), sql.Identifier(username)
            )
        )
        statements.append(
            sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT ON TABLES TO {}").format(
                sql.Identifier(schema_priv.schema), sql.Identifier(username)
            )
        )
    if schema_priv.write:
        statements.append(
            sql.SQL("GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}").format(
                sql.Identifier(schema_priv.schema), sql.Identifier(username)
            )
        )
        statements.append(
            sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT INSERT, UPDATE, DELETE ON TABLES TO {}").format(
                sql.Identifier(schema_priv.schema), sql.Identifier(username)
            )
        )
    with cursor(conn) as cur:
        for statement in statements:
            cur.execute(statement)


def apply_privileges(settings: Settings, username: str, selections: List[SchemaPrivilege]) -> None:
    grouped: Dict[str, List[SchemaPrivilege]] = defaultdict(list)
    for item in selections:
        item.ensure_write_implies_read()
        grouped[item.database].append(item)
    for db_name, items in grouped.items():
        with db_connection(settings, db_name) as conn:
            existing = fetch_schema_privileges(conn, username)
            for item in items:
                if not item.read and not item.write:
                    if item.schema in existing:
                        revoke_privileges(conn, username, item.schema)
                    continue
                grant_privileges(conn, username, item)


def purge_user_privileges(settings: Settings, username: str) -> None:
    """Best-effort revoke privileges and default privileges across accessible databases."""
    try:
        with db_connection(settings) as base_conn:
            databases = list_databases(base_conn)
    except Exception:
        databases = []
    if settings.database and settings.database not in databases:
        databases.append(settings.database)
    databases = list(dict.fromkeys(databases))
    for db_name in databases:
        try:
            with db_connection(settings, db_name) as conn:
                schemas = list_schemas(conn)
                owners = list_default_privilege_owners(conn)
                for schema in schemas:
                    revoke_privileges(conn, username, schema)
                    revoke_default_privileges(conn, username, schema, owners)
        except Exception:
            continue


def build_privilege_matrix(settings: Settings, username: Optional[str] = None) -> List[SchemaPrivilege]:
    selections: List[SchemaPrivilege] = []
    try:
        with db_connection(settings) as base_conn:
            databases = list_databases(base_conn)
    except Exception:
        databases = []

    # Always include the configured database as a fallback target.
    if settings.database and settings.database not in databases:
        databases.append(settings.database)
    # De-duplicate while preserving order.
    databases = list(dict.fromkeys(databases))
    if not databases:
        return selections

    for db_name in databases:
        try:
            with db_connection(settings, db_name) as db_conn:
                schemas = list_schemas(db_conn)
                if username:
                    try:
                        existing = fetch_schema_privileges(db_conn, username)
                    except Exception:
                        existing = {}
                else:
                    existing = {}
                for schema in schemas:
                    base = existing.get(schema)
                    selections.append(
                        SchemaPrivilege(
                            database=db_name,
                            schema=schema,
                            read=base.read if base else False,
                            write=base.write if base else False,
                        )
                    )
        except Exception:
            # Skip databases we cannot connect to (e.g., shared/catalog databases)
            continue
    return selections


# ----------- Curses helpers ----------- #
def draw_centered(stdscr, text: str, y: Optional[int] = None) -> None:
    height, width = stdscr.getmaxyx()
    line = text[: width - 2]
    xpos = max((width - len(line)) // 2, 0)
    ypos = y if y is not None else max(height // 2, 0)
    stdscr.addstr(ypos, xpos, line)


def render_header(stdscr, settings: Settings, subtitle: str = "") -> int:
    height, width = stdscr.getmaxyx()
    row = 0
    left_padding = 1
    word_offset = 2  # modest offset to align label under art without drifting too far
    for art in HEADER_ART:
        if row >= height - 2:
            break
        # Left-leaning header placement for a grounded feel.
        stdscr.addstr(row, left_padding, art[: max(0, width - 2 - left_padding)], COLOR_HEADER)
        row += 1
    if row < height - 1:
        stdscr.addstr(row, left_padding + word_offset, "Redshift User Manager", COLOR_HEADER)
        row += 1
    if row < height - 1:
        conn_info = f"Connected: {settings.user}@{settings.host}:{settings.port}/{settings.database}"
        stdscr.addstr(row, left_padding, conn_info[: max(0, width - 2 - left_padding)], COLOR_DIM)
        row += 1
    if subtitle and row < height - 1:
        stdscr.addstr(row, 1, subtitle[: max(0, width - 2)], COLOR_NORMAL | curses.A_BOLD)
        row += 1
    return min(row + 1, height - 1)


def render_footer(stdscr, text: str) -> None:
    height, width = stdscr.getmaxyx()
    stdscr.addstr(height - 1, 0, text[: width - 1], COLOR_DIM)


def prompt_text(
    stdscr,
    prompt: str,
    allow_empty: bool = False,
    hidden: bool = False,
    settings: Optional[Settings] = None,
) -> str:
    curses.curs_set(1)
    buffer: List[str] = []
    while True:
        stdscr.clear()
        row = 0
        if settings:
            row = render_header(stdscr, settings)
        stdscr.addstr(row, 0, prompt)
        render_footer(stdscr, "Enter to submit • Esc to cancel")
        stdscr.refresh()
        buffer.clear()
        pos = 0
        input_row = row + 2
        while True:
            ch = stdscr.getch(input_row, pos)
            if ch in (curses.KEY_ENTER, 10, 13):
                text = "".join(buffer).strip()
                if text or allow_empty:
                    curses.curs_set(0)
                    return text
                break
            if ch == 27:  # ESC
                curses.curs_set(0)
                return ""
            if ch in (curses.KEY_BACKSPACE, 127):
                if buffer:
                    buffer.pop()
                    pos -= 1
                    stdscr.addstr(input_row, pos, " ")
                    stdscr.move(input_row, pos)
                continue
            if 32 <= ch <= 126:
                buffer.append(chr(ch))
                stdscr.addstr(input_row, pos, "*" if hidden else buffer[-1])
                pos += 1
        stdscr.addstr(input_row + 2, 0, "Input required. Press any key to retry.")
        stdscr.getch()


def menu(
    stdscr,
    title: str,
    options: Iterable[str],
    selected: int = 0,
    settings: Optional[Settings] = None,
) -> Optional[int]:
    options = list(options)
    if not options:
        return None
    index = selected
    while True:
        stdscr.clear()
        if settings:
            content_start = render_header(stdscr, settings, subtitle=title)
        else:
            stdscr.addstr(0, 0, title)
            content_start = 2
        height, width = stdscr.getmaxyx()
        render_footer(stdscr, "Arrows navigate • Enter selects • Esc/q to go back")
        footer_line = height - 1
        visible_height = max(1, footer_line - content_start)
        start = max(0, min(index - visible_height // 2, len(options) - visible_height))
        for i, option in enumerate(options[start : start + visible_height]):
            line_index = start + i
            prefix = "➤ " if line_index == index else "  "
            display = option[: width - 4]
            attr = COLOR_HIGHLIGHT if line_index == index else COLOR_NORMAL
            stdscr.addstr(content_start + i, 0, f"{prefix}{display}", attr)
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord("q"), 27):
            return None
        if key in (curses.KEY_DOWN, ord("j")):
            index = (index + 1) % len(options)
        elif key in (curses.KEY_UP, ord("k")):
            index = (index - 1) % len(options)
        elif key in (curses.KEY_ENTER, 10, 13):
            return index


def checkbox_menu(stdscr, title: str, items: List[SchemaPrivilege], settings: Settings) -> List[SchemaPrivilege]:
    index = 0
    while True:
        stdscr.clear()
        content_start = render_header(stdscr, settings, subtitle=title)
        height, width = stdscr.getmaxyx()
        render_footer(
            stdscr, "Arrows move • R toggles read • W toggles write (and read) • Enter confirm • Esc/q back"
        )
        footer_line = height - 1
        visible_height = max(1, footer_line - content_start)
        start = max(0, min(index - visible_height // 2, len(items) - visible_height))
        for i, item in enumerate(items[start : start + visible_height]):
            line_index = start + i
            prefix = "➤ " if line_index == index else "  "
            label = item.label()
            attr = COLOR_HIGHLIGHT if line_index == index else COLOR_NORMAL
            stdscr.addstr(content_start + i, 0, (prefix + label)[: width - 1], attr)
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord("q"), ord("Q"), 27):
            return items
        if key in (curses.KEY_DOWN, ord("j")):
            index = (index + 1) % len(items)
        elif key in (curses.KEY_UP, ord("k")):
            index = (index - 1) % len(items)
        elif key in (ord("r"), ord("R")):
            items[index].read = not items[index].read
            if not items[index].read:
                items[index].write = False
        elif key in (ord("w"), ord("W")):
            items[index].write = not items[index].write
            if items[index].write:
                items[index].read = True
        elif key in (curses.KEY_ENTER, 10, 13):
            return items


def confirm(stdscr, question: str, settings: Settings) -> bool:
    choice = menu(stdscr, question, ["No", "Yes"], settings=settings)
    return choice == 1


def alert(stdscr, message: str) -> None:
    stdscr.clear()
    lines = message.splitlines() or [message]
    height, width = stdscr.getmaxyx()
    start_row = max((height - len(lines)) // 2, 0)
    for i, line in enumerate(lines):
        stdscr.addstr(start_row + i, 1, line[: max(0, width - 2)])
    render_footer(stdscr, "Press any key to continue.")
    stdscr.getch()


# ----------- Main workflows ----------- #
def choose_database(stdscr, settings: Settings) -> Optional[str]:
    """Let the admin pick which database to manage."""
    options: List[str] = []
    try:
        with db_connection(settings) as conn:
            options = list_databases(conn)
    except Exception:
        options = []
    if settings.database and settings.database not in options:
        options.insert(0, settings.database)
    options = list(dict.fromkeys(options))
    if not options:
        alert(stdscr, "No databases found or accessible.")
        return None
    choice = menu(stdscr, "Select database to manage users", options, settings=settings)
    if choice is None:
        return None
    return options[choice]


def flow_create_user(stdscr, settings: Settings) -> None:
    username = prompt_text(stdscr, "New username:", allow_empty=False, settings=settings)
    if not username:
        return
    validation_error = validate_username(username)
    if validation_error:
        alert(stdscr, validation_error)
        return
    password = prompt_text(
        stdscr, "Password (leave empty to auto-generate):", allow_empty=True, hidden=True, settings=settings
    )
    auto_generated = False
    if not password:
        password = generate_password()
        auto_generated = True
    privileges = build_privilege_matrix(settings)
    if not privileges:
        alert(stdscr, "No databases/schemas found or accessible. Check your connection and permissions.")
        return
    privileges = checkbox_menu(stdscr, "Select privileges (read/write per schema)", privileges, settings)
    if not confirm(stdscr, f"Create user {username} with selected privileges?", settings):
        return
    try:
        with db_connection(settings) as conn:
            create_user(conn, username, password)
        apply_privileges(settings, username, privileges)
        if auto_generated:
            alert(
                stdscr,
                "\n".join(
                    [
                        f"User {username} created.",
                        "Connection details:",
                        f"  user: {username}",
                        f"  password: {password}",
                        f"  host: {settings.host}",
                        f"  port: {settings.port}",
                    ]
                ),
            )
        else:
            alert(stdscr, f"User {username} created.")
    except Exception as exc:
        alert(stdscr, f"Error creating user: {exc}")


def flow_reset_password(stdscr, settings: Settings, username: str) -> None:
    password = prompt_text(
        stdscr, "New password (empty = auto-generate):", allow_empty=True, hidden=True, settings=settings
    )
    if not password:
        password = generate_password()
    try:
        with db_connection(settings) as conn:
            reset_password(conn, username, password)
        alert(stdscr, f"Password reset. New password: {password}")
    except Exception as exc:
        alert(stdscr, f"Error resetting password: {exc}")


def flow_modify_privileges(stdscr, settings: Settings, username: str) -> None:
    privileges = build_privilege_matrix(settings, username=username)
    if not privileges:
        alert(stdscr, "No databases/schemas found or accessible. Check your connection and permissions.")
        return
    updated = checkbox_menu(stdscr, f"Update privileges for {username}", privileges, settings)
    if not confirm(stdscr, f"Apply privilege changes to {username}?", settings):
        return
    try:
        apply_privileges(settings, username, updated)
        alert(stdscr, "Privileges updated.")
    except Exception as exc:
        alert(stdscr, f"Error updating privileges: {exc}")


def flow_delete_user(stdscr, settings: Settings, username: str) -> None:
    if not confirm(stdscr, f"Delete user {username}?", settings):
        return
    try:
        purge_user_privileges(settings, username)
        with db_connection(settings) as conn:
            drop_user(conn, username)
        alert(stdscr, f"User {username} deleted.")
    except Exception as exc:
        alert(stdscr, f"Error deleting user: {exc}")


def flow_existing_user(stdscr, settings: Settings, username: str) -> None:
    choice = menu(
        stdscr,
        f"User: {username}",
        ["Back", "Modify privileges", "Reset password", "Delete user"],
        selected=1,
        settings=settings,
    )
    if choice == 1:
        flow_modify_privileges(stdscr, settings, username)
    elif choice == 2:
        flow_reset_password(stdscr, settings, username)
    elif choice == 3:
        flow_delete_user(stdscr, settings, username)


def main(stdscr) -> None:
    curses.curs_set(0)
    stdscr.nodelay(False)
    ensure_dependencies()
    settings = load_settings()
    init_colors()
    selected_db = choose_database(stdscr, settings)
    if not selected_db:
        return
    settings.database = selected_db
    while True:
        try:
            with db_connection(settings) as conn:
                users = list_users(conn)
        except Exception as exc:
            alert(stdscr, f"Connection error: {exc}")
            return
        menu_items = ["+ Create new user"] + users + ["Quit"]
        selection = menu(stdscr, "Select an option", menu_items, settings=settings)
        if selection is None or menu_items[selection] == "Quit":
            break
        if selection == 0:
            flow_create_user(stdscr, settings)
        else:
            flow_existing_user(stdscr, settings, users[selection - 1])


if __name__ == "__main__":
    curses.wrapper(main)
