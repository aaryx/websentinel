# Recorded validation evidence

Machine-generated local validation results live here. These are point-in-time
measurements, not promises about all environments. `endurance.json` records the
five-minute mixed-response loopback run; Python traced allocation measurements
are not process RSS. Reproduce with:

```console
python scripts/endurance.py --seconds 300 --concurrency 10 --output evidence/endurance.json
```
