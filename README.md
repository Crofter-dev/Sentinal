honeypot/
├── server.py                    ← SSH server, entry point, run this
├── dump.py                      ← docker-py container spawner
├── shell.c                      ← a bash shell made for dropping later
├── capture/
│   ├── capture.py               ← session recorder, keystroke timing
│   └── credential.py            ← regex patterns for all credential types
└── db/
    └── honeypot.db              ← SQLite schema
