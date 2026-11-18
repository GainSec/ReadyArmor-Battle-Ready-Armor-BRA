# API reference

Boots provides HTTP routes and WebSocket connections for the browser and integrations.
Start the server before making API requests. Interactive API documentation is available at `/docs`.

## Authentication

Use the server access token for ordinary API requests.

```bash
curl --header "Authorization: Bearer $BRA_ACCESS_TOKEN" \
  http://127.0.0.1:9999/api/engagement
```

Set `BRA_ACCESS_TOKEN` to the token from server startup.
The 2x4 routes use a separate service token. Takeover operations also require the active lease header.
Browser sessions can use the configured authentication cookies.

## Main resources

| Resource | Function |
| --- | --- |
| `/api/config` | Read and update server settings. |
| `/api/engagement` | Read engagement state. |
| `/api/findings` | Read finding records. |
| `/api/artifacts` | Read the artifact tree. |
| `/api/logs` | Read available logs. |
| `/api/anon/*` | Manage privacy settings and mappings as the operator. |
| `/api/proxy/*` | Control and inspect the local model proxy. |
| `/api/2x4/*` | Supply bounded assistant access. |

Use the interactive schema for request fields and response types.
The route handler column identifies the function in `boots/main.py`.

## Route inventory

| Method | Route | Handler |
| --- | --- | --- |
| `GET` | `/api/config` | `get_config` |
| `POST` | `/api/config` | `set_config` |
| `GET` | `/api/proxy/status` | `proxy_status` |
| `POST` | `/api/proxy/start` | `proxy_start` |
| `POST` | `/api/proxy/stop` | `proxy_stop` |
| `GET` | `/api/engagement` | `get_engagement` |
| `GET` | `/api/summary` | `get_summary` |
| `GET` | `/api/report` | `get_report` |
| `GET` | `/api/live/status` | `get_live_status` |
| `POST` | `/api/live/start` | `start_live` |
| `POST` | `/api/live/stop` | `stop_live` |
| `POST` | `/api/live/spawn` | `spawn_tmux` |
| `POST` | `/api/live/kill` | `kill_tmux` |
| `POST` | `/api/live/scroll` | `scroll_terminal` |
| `POST` | `/api/live/send` | `send_to_terminal` |
| `GET` | `/api/chat` | `get_chat` |
| `POST` | `/api/chat` | `send_chat` |
| `GET` | `/api/chat/pending` | `get_pending_chat` |
| `POST` | `/api/chat/respond` | `respond_chat` |
| `DELETE` | `/api/chat` | `clear_chat` |
| `POST` | `/api/control` | `send_control` |
| `GET` | `/api/control` | `get_control` |
| `GET` | `/api/pitches` | `get_pitches` |
| `POST` | `/api/pitches/{filename}/proposal` | `update_proposal` |
| `POST` | `/api/pitches/{filename}/ingest` | `ingest_pitches` |
| `GET` | `/api/leads` | `get_leads` |
| `GET` | `/api/intel` | `get_intel` |
| `GET` | `/api/findings` | `get_findings` |
| `GET` | `/api/health` | `get_health` |
| `GET` | `/api/governance` | `get_governance` |
| `POST` | `/api/governance/token/{name}/toggle` | `toggle_token` |
| `POST` | `/api/governance/generated-token` | `create_generated_token` |
| `GET` | `/api/anon/mappings` | `get_anon_mappings` |
| `POST` | `/api/anon/mappings` | `add_anon_mapping` |
| `POST` | `/api/anon/detect` | `anon_detect` |
| `POST` | `/api/anon/apply` | `anon_apply` |
| `GET` | `/api/anon/config` | `get_anon_config` |
| `POST` | `/api/anon/config` | `set_anon_config` |
| `GET` | `/api/stats` | `get_stats` |
| `GET` | `/api/lessons` | `get_lessons` |
| `GET` | `/api/roe` | `get_roe` |
| `GET` | `/api/docs/auth/status` | `docs_auth_status` |
| `POST` | `/api/docs/auth` | `docs_auth_login` |
| `GET` | `/api/debug/auth/status` | `debug_auth_status` |
| `POST` | `/api/debug/auth` | `debug_auth_login` |
| `GET` | `/api/debug/env` | `get_debug_env` |
| `GET` | `/api/debug/token-usage` | `get_debug_token_usage` |
| `GET` | `/api/docs` | `get_docs` |
| `GET` | `/api/docs/{category}/{filename}` | `get_doc_content` |
| `GET` | `/api/loadout` | `get_loadout` |
| `GET` | `/api/telemetry` | `get_telemetry` |
| `GET` | `/api/manager/portfolio` | `get_manager_portfolio` |
| `GET` | `/api/overrides` | `get_overrides` |
| `POST` | `/api/overrides/enable-all` | `enable_all_overrides` |
| `POST` | `/api/overrides/disable-all` | `disable_all_overrides` |
| `POST` | `/api/overrides/{rule_id}/enable` | `enable_override` |
| `POST` | `/api/overrides/{rule_id}/disable` | `disable_override` |
| `POST` | `/api/overrides` | `add_override` |
| `DELETE` | `/api/overrides/{rule_id}` | `remove_override` |
| `GET` | `/api/artifacts` | `get_artifacts` |
| `GET` | `/api/artifacts/{path:path}` | `get_artifact` |
| `GET` | `/api/engagement-file/{path:path}` | `get_engagement_file` |
| `GET` | `/api/logs` | `get_logs` |
| `GET` | `/api/logs/{name}` | `get_log_content` |
| `WEBSOCKET` | `/ws/logs` | `websocket_logs` |
| `WEBSOCKET` | `/ws/chat/numbuh_2x4` | `websocket_chat_numbuh_2x4` |
| `WEBSOCKET` | `/ws/engage` | `websocket_engage` |
| `GET` | `/api/engage/state` | `get_engage_state` |
| `GET` | `/api/2x4/summary` | `get_2x4_summary` |
| `GET` | `/api/2x4/file` | `get_2x4_file` |
| `GET` | `/api/2x4/log` | `get_2x4_log` |
| `GET` | `/api/2x4/engage-status` | `get_2x4_engage_status` |
| `POST` | `/api/2x4/engage-action` | `post_2x4_engage_action` |
| `POST` | `/api/2x4/call/continue` | `post_2x4_call_continue` |
| `POST` | `/api/2x4/call/speak` | `post_2x4_call_speak` |
| `GET` | `/api/2x4/call/status` | `get_2x4_call_status` |
| `POST` | `/api/2x4/call/stop` | `post_2x4_call_stop` |
| `POST` | `/api/2x4/takeover-confirm` | `post_2x4_takeover_confirm` |
| `POST` | `/api/2x4/stand-down` | `post_2x4_stand_down` |
| `GET` | `/api/processes` | `list_processes` |
| `POST` | `/api/processes/{pid}/kill` | `kill_process` |
| `POST` | `/api/processes/kill-all-agents` | `kill_all_agents` |
| `GET` | `/api/cloudflared/tunnel/status` | `cloudflared_tunnel_status` |
| `POST` | `/api/cloudflared/tunnel/start` | `cloudflared_tunnel_start` |
| `POST` | `/api/cloudflared/tunnel/stop` | `cloudflared_tunnel_stop` |
| `GET` | `/api/engage/download/{filename}` | `download_packup` |
| `GET` | `/api/harness` | `list_harnesses` |
| `GET` | `/api/harness/{name}/prompt` | `get_harness_prompt` |
| `POST` | `/api/harness/{name}/run` | `run_harness` |
| `GET` | `/preview` | `serve_preview` |
| `GET` | `/manager` | `serve_manager_frontend` |
| `GET` | `/` | `serve_frontend` |
