# BACKUPS Template (Recurring)


Use a separate copy of this form for each engagement. Record the backup schedule, storage, integrity checks, and handling rules.

## Schedule
- Frequency: [on first successful run; before deletion of any file(s); and recurring: daily/weekly/etc.]
- Window/blackouts: [ ]

## Scope
- Data to include: layer3-engagement/NOTES/, PoCs, evidence, reports, manifests.
- Data to exclude: [ ]
- Paths: [source paths]

## Storage
- Destination: `BACKUPS/<name-scheme>/` by default.
- Create a new backup set for each run.
- Do not overwrite or append to earlier backup sets.
- Encryption: [method/keys]
- Retention: Monitor the total `BACKUPS/` size.
- If the total exceeds 10 GiB, include this message in every response:
  “BACKUPS has hit 10 GiB and should be moved manually.”
- Document the manual movement and rotation procedure separately.

## Integrity
- Hashing/checksums: [process]
- Verification cadence: [e.g., monthly test restore]

## Special Handling
- Secrets/high-sensitivity handling: [ ]
- Additional constraints (from scope/ROE): [ ]
