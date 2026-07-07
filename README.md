honeypot/
├── server.py                    ← SSH server, entry point, run this
├── integration_example.py       ← docker-py container spawner
├── seccomp-profile.json         ← container syscall filter
├── capture/
│   ├── capture.py               ← session recorder, keystroke timing
│   └── credential_extractor.py  ← regex patterns for all credential types
└── db/
    └── schema.sql               ← SQLite schema
