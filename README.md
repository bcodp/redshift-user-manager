# Redshift User Manager

Interactive terminal UI to manage Redshift users: create, reset passwords, grant/revoke per-schema privileges (read or read/write), and delete users. Uses curses for navigation.

## Features
- Loads connection settings from `.env`.
- Arrow-key navigation, highlighted selections, and checkbox-style privilege toggles.
- Create users (auto-generate strong 24-char password if left empty).
- Modify privileges for existing users (R toggles read, W toggles write+read).
- Reset passwords, delete users.
- Database picker at startup to choose which DB to manage.

## Requirements
- Python 3.10+ recommended (3.9–3.12 works).
- Dependencies in `requirements.txt`:
  - `psycopg2-binary`
  - `python-dotenv`

Install:  
```bash
pip install -r requirements.txt
```

## Configuration
Create a `.env` (see `.env.example`):
```
REDSHIFT_HOST=your-cluster-endpoint
REDSHIFT_PORT=5439
REDSHIFT_USER=admin_user
REDSHIFT_PASSWORD=admin_password
REDSHIFT_DATABASE=dev
```

Use an admin-capable account so it can list databases/schemas and manage users.

## Usage
```bash
python redshift_user_manager.py
```

Controls:
- Menus: arrows to navigate; Enter select; Esc/q back/quit.
- Privileges: `R` toggles read; `W` toggles write (enables read).
- Prompts: Enter submit; Esc cancel.

Flows:
- Choose database to manage at startup.
- Create user: set username, optional password (auto-generated if empty), then choose schema privileges.
- Modify user: adjust privileges, reset password, or delete. Deletion revokes grants/default grants first.

When an auto-generated password is used, the tool displays copy-ready connection details (user, password, host, port).

