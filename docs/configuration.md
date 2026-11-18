# Configuration

## Paths

The repository root contains `boots/`, `head/`, and `body/`.
The engagement root is `body/`. Its `.bra/` directory contains state for that engagement.

| Path | Contents |
| --- | --- |
| `boots/.bra-gui-config.json` | Web interface settings |
| `boots/.bra-gui-token` | Web access token |
| `~/.bra-tui-config.json` | Python command settings |
| `body/.bra/approvals/` | Persistent approval tokens |
| `body/.bra/one-time-approvals/` | Invocation and scope-grant files with type-specific matching and consumption |
| `body/.bra/ui/config.json` | Active UI profile |
| `body/.bra/anon_map.json` | Sensitive values and their aliases |

Use the interface to change engagement permissions. Runtime files contain separate operator, system, and agent access classes.

## Environment variables

| Variable | Function |
| --- | --- |
| `BRA_GUI_HOST` | Set the launcher host. |
| `BRA_GUI_PORT` | Set the launcher port. |
| `BRA_GUI_DIR` | Set the launcher engagement root. |
| `BRA_DIR` | Supply the server engagement root. |
| `BRA_MODEL` | Select the model. |
| `ANTHROPIC_API_KEY` | Supply the model access key. |
| `BRA_PYTHON_EXECUTABLE` | Select the interpreter for body scripts. |
| `BRA_PROXY_BACKEND_URL` | Set an OpenAI-compatible backend URL. |
| `BRA_PROXY_BACKEND_API_KEY` | Supply the backend access key. |
| `BRA_PROXY_PORT` | Set the local proxy port. |
| `BRA_PROXY_CONTEXT_WINDOW` | Set the proxy context limit. |
| `BRA_PROXY_MAX_COMPLETION_TOKENS` | Set the completion limit. |

Environment model and access-key values take precedence over saved Python settings.
A backend URL supplied through the environment enables proxy routing.
Saved proxy configuration requires a backend URL and `proxy_enabled`.

## Model routing

The agent uses the Claude Agent SDK. A configured model selects the model for the request.
An empty model setting uses the SDK default.

The proxy router starts a local LiteLLM process. It translates Anthropic-format requests into requests for an OpenAI-compatible backend.
`proxy_model_map` associates SDK model names with backend model names.

| Setting | Default |
| --- | --- |
| `proxy_port` | `4000` |
| `proxy_context_window` | `32768` |
| `proxy_max_completion_tokens` | `8192` |

The completion limit is a fixed maximum. BRA does not calculate a new limit from each prompt length.

1. Open the Proxy Router settings.
2. Enter the backend URL.
3. Enter the backend key if required.
4. Set the model mapping.
5. Set the context and completion limits for that model.
6. Enable the proxy.
7. Examine the proxy status before starting an engagement.

## UI resources

Profile lookup uses this order:

1. `body/layer3-engagement/UI/profiles/`
2. `body/.bra/ui/profiles/`
3. `body/layer2-templates/ui/profiles/`

The `packs/` and `assets/` directories use the same engagement, state, and template order.
