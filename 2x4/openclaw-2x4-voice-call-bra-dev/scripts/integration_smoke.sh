#!/usr/bin/env bash
set -euo pipefail

PLUGIN_DIR="$HOME/.openclaw/extensions/voice-call-bra"
MANIFEST="$PLUGIN_DIR/openclaw.plugin.json"

if [ ! -f "$MANIFEST" ]; then
  echo "[FAIL] Missing manifest: $MANIFEST"
  exit 1
fi

python3 -c "import json, pathlib, sys; m = json.loads(pathlib.Path(sys.argv[1]).read_text()); assert m.get('id') == 'voice-call-bra'; props = m.get('configSchema', {}).get('properties', {}); assert 'vibevoice' in props; assert set(props['vibevoice']['properties'].keys()) >= {'enabled', 'wsBaseUrl', 'voice', 'cfg', 'steps', 'timeoutMs'}; print('TEST_MANIFEST_OK', m.get('id'))" "$MANIFEST"

echo "TEST_OPENCLAW_INFO_BEGIN"
openclaw plugins info voice-call-bra | sed -n '1,12p'
echo "TEST_OPENCLAW_INFO_END"

if [ -f /tmp/vv_smoke_3004_pass.csv ]; then
  echo "TEST_VV_SMOKE_PRECHECK_PRESENT /tmp/vv_smoke_3004_pass.csv"
else
  echo "TEST_VV_SMOKE_PRECHECK_MISSING"
fi

echo "TEST_PASS"
