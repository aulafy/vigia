# Local AI: explanations and client drafts (optional)

With a local model in [Ollama](https://ollama.com), every alert in the dashboard gets two buttons:

- **Explain**: what is happening, the real risk for this client, numbered steps to fix it, and how to check that it is fixed. Written for you, the technician.
- **Draft for the client**: a short message without jargon for the client's contact, explaining what was found and asking for what you need (permission, a time slot, access). It starts with `[Name]` and ends with `[Your name]`, ready to copy into an e-mail or WhatsApp.

Both appear under the alert, marked **AI draft**, with Copy, Regenerate and Close buttons. Vigía's own alerts (feeds, channels, the weekly test) only get **Explain**, since there is no client to write to.

## What it does not do

The AI is **outside the alerting path**. Vigía's rules decide priorities, who gets paged, and when, exactly as before. The model never:

- changes a priority, acknowledges an alert or accepts a change;
- sends anything: no e-mail, no message, no notification;
- runs on its own: only when you press a button.

Without `OLLAMA_MODEL`, the buttons do not appear and Vigía works exactly as before.

## Grounded in Vigía's facts

A model asked to explain "no DMARC record" with nothing else will happily fill in the gaps. In testing, `qwen3.5:9b` told us to fix the DNS "at GoDaddy or Cloudflare" for a domain registered at NameCheap. So for every alert, Vigía sends the model **only what it actually knows** about it:

| Alert | Facts sent |
|---|---|
| Down, TLS, page content | Last HTTP status, response time, certificate days left, failures in a row |
| Domain, DNS, SPF/DMARC | Registrar and transfer lock (RDAP), nameservers, mail servers, current SPF and DMARC records |
| OSV, WordPress, KEV, end-of-life | The component involved and its version |
| Edge devices | Device name, product, declared version, management and portal addresses |
| Backups | Job, last success and failure (with its message), last restore test, last size |
| Every alert | Priority, title, detail, client, asset, criticality, exploitation probability (EPSS), maintenance window |

Every fact Vigía does **not** have is listed explicitly as unknown, and the instructions forbid guessing it. With the registrar known, the same model answered "open the DNS panel at NameCheap, Inc., the domain's registrar".

The alert text can contain words from public feeds (advisory titles, research posts). It is fenced as data, and the model is told to ignore any instruction inside it. Since the output is only shown to you and nothing acts on it, a manipulated text could at worst produce a bad draft, which you review anyway.

## Setup

1. Install Ollama and pull a model (8 GB of free RAM or more for a 9B model):

   ```bash
   ollama pull qwen3.5:9b
   ```

2. Add it to `.env` and restart Vigía:

   ```bash
   OLLAMA_MODEL=qwen3.5:9b
   # OLLAMA_URL=http://127.0.0.1:11434   # default; another machine on your network works too
   # OLLAMA_TIMEOUT_S=120
   ```

3. **Settings → Local AI** shows whether the model is installed and reachable.

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_MODEL` | — (off) | The model name as `ollama list` shows it. Setting it enables the buttons. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Where Ollama listens |
| `OLLAMA_TIMEOUT_S` | `120` | Give up on one answer after this |

**With Docker:** Ollama runs on the host, so point the container to it, for example `OLLAMA_URL=http://host.docker.internal:11434` (Docker Desktop) or the host's IP on Linux.

## Choosing a model

Measured on a MacBook Air (M4, 24 GB) with a real alert:

| Model | One answer | Quality |
|---|---|---|
| `qwen3.5:9b` (MLX build) | ~20–30 s | Good explanations and client messages, follows the facts |
| `llama3.2:3b` | ~8 s | Vague and repetitive; not good enough for client messages |

A 7–9B instruction-tuned model is the sweet spot. Larger models write better, but take longer on a laptop. Vigía runs one generation at a time (a laptop has one GPU), and caches each answer until the alert changes. **Regenerate** asks for a new one.

## Privacy

Everything stays on your machine, or on the Ollama host you choose. Client names, domains and versions never go to a cloud API. Prompts are not logged.

## API

`POST /api/ai/explain?key=<alert key>&lang=es|en` and `POST /api/ai/client?key=…` (dashboard authentication and the `x-vigia-ui` header) return `{ text, model, ms, ai: true, cached? }`. Add `regen=1` to skip the cache. Errors: `503` AI disabled, `404` unknown alert, `504` timeout, `502` Ollama error.
