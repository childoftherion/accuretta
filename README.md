<div align="center">

<img src="logo-mark.png" alt="Accuretta logo" width="140" />

# Accuretta

**A fully local AI workspace. Your model, your files, your machine.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Powered by llama.cpp](https://img.shields.io/badge/powered%20by-llama.cpp-orange.svg)](https://github.com/ggerganov/llama.cpp)
[![100% Local](https://img.shields.io/badge/100%25-local-brightgreen.svg)](#privacy)
[![No Telemetry](https://img.shields.io/badge/telemetry-none-success.svg)](#privacy)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#quick-start)

<br />

<a href="https://github.com/user-attachments/assets/ff7ff8b8-56f9-4393-b4fa-1538a99b87f7" title="Click to play the demo video">
  <img src="media/demo-poster.png" alt="Accuretta demo. Click to play." width="780" />
</a>

<sub>Click the image above to watch the demo (about 23 seconds, 1.9 MB).</sub>

</div>

<br />

## What it is

Accuretta is a small, friendly desktop AI workspace that runs entirely on your computer. You drop a GGUF model file in a folder, point it at the binary, and you get a chat UI with real tool use, a live HTML preview pane, a Python syntax checker, and a workspace tree that lets the model read and write files you choose. The bridge talks to llama.cpp through llama-server, so you get the speed and the knobs without having to wire up the whole stack yourself.

It is built on a few HTML files, one CSS file, one JS file, and one Python file. No build step, no npm, no electron wrapper. You can read every line in an afternoon.

## Why I made it

This started as a personal frustration. I had been paying for cloud AI subscriptions and watching the goalposts shift every few weeks. One service trimmed quotas. Another quietly swapped the model behind the same name. Then I tried Google Antigravity, decided I was tired of renting tools that could change under me, and started building something I actually owned.

The two rules from day one:

1. The model lives on my disk. Nothing leaves the computer unless I explicitly ask.
2. No subscriptions. The GPU is already paid for.

I came in fresh from Ollama and figured llama.cpp would be a sidegrade. It was not. Same hardware, same model file, noticeably faster generation, and clean control over things like KV cache quantization, flash attention, and speculative decoding. The tradeoff is that you wire it up yourself. Accuretta is partly that wiring, dressed up in a UI you can actually use.

## A look at the agent in action

The agent has hands. It can read files, write files, run commands, fetch web pages, take screenshots, and inspect network state. Anything destructive (file writes, shell commands) is gated by an approval card, so nothing dangerous happens silently. Read style actions like web fetches can run automatically depending on the model and your settings.

<p align="center">
  <img src="media/screenshot.png" alt="Agent writing a haiku to disk after exploring an empty workspace folder" width="780" />
</p>

<p align="center"><em>Above: the model picks up that the workspace is empty, decides to write a haiku to <code>haiku.txt</code>, and the file lands on disk. The session, the workspace, and the model are all visible in one place.</em></p>

A more interesting example. Below the model is asked to run a network snapshot, group active TCP connections by process, flag anything suspicious, and summarize recent DNS activity. It calls the snapshot tool, gets back a structured payload, then reasons about it in a real markdown table. No round trip to a cloud, no API key, no rate limit.

<p align="center">
  <img src="media/network_sniff_investigation.png" alt="Agent running a network snapshot tool and producing a TCP analysis grouped by process" width="780" />
</p>

One more, from a real session. I asked the agent to help tune my in-ear monitors (Linsoul 7Hz x Crinacle Zero:2) using Peace Equalizer APO. It searched audio review sites, Reddit threads, and AutoEQ measurement databases, picked a target curve (Harman In-Ear 2019), generated ten parametric filters with the right gain/Q/frequency for that specific IEM, and wrote a complete `.peace` profile straight into the EqualizerAPO config folder — including a PreAmp setting to prevent clipping and a heads-up that one of the boosts was unusually aggressive. No copy-pasting filters from a forum. No translating frequency tables into config syntax by hand. Ask, approve the writes, done.

<p align="center">
  <img src="media/Sound_Question_and_search.png" alt="Agent researching IEM tuning across reference-audio-analyzer.pro, audiosciencereview.com, head-fi.org, and Reddit" width="780" />
</p>

<p align="center"><em>Above: the agent searches reference-audio-analyzer.pro, audiosciencereview.com, head-fi.org, and Reddit for measurements and recommended targets for the specific IEMs.</em></p>

<p align="center">
  <img src="media/sound_profile_applied_by_accuretta.png" alt="Agent writing a complete Peace Equalizer profile to disk with activation instructions" width="780" />
</p>

<p align="center"><em>Above: ten parametric filters written to <code>C:\Program Files\EqualizerAPO\config\Qwen_Optimized.peace</code>, with clear activation steps and a frank note about the more aggressive corrections so I could dial them back if I wanted.</em></p>

## What you get

* **Chat with real tool use.** Read files, write files, run shell commands, fetch URLs, take screenshots, inspect processes and network state. Every destructive call goes through an approval card.
* **Live HTML preview.** When the model writes a webpage, you see it render next to the conversation. Switch between rendered view and source with one click.
* **Open existing HTML from your workspace.** Click the lightning bolt next to any `.html` file in the workspace tree and it loads into the preview pane with its real CSS, JS, and images intact. The bridge serves through a hardened endpoint with strict path traversal checks, so the iframe can only ever reach files inside the folder you opened.
* **Python syntax checker.** Click the checkmark next to any `.py` file and the bridge runs `compile()` on it. You get a green banner if it parses, or a red one with the line, column, and message. Nothing executes. No imports run. No risk.
* **Approval cards for everything destructive.** File writes and shell commands always prompt. Read style calls like web fetches can run automatically when you trust the model with that.
* **Conversation history on disk.** Sessions live in a folder you control. Branch them, rename them, delete them. Nothing is locked into a database.
* **A real settings drawer.** Context window, sampler temperature, top p, top k, KV cache type, GPU layers, batch size, thinking budget, model swap. All on the fly with a quick reload.
* **Mobile aware UI.** The whole thing works on a phone browser. Composer, sidebar, settings, swipe back to chat from the menu. No app store, no install, just open the localhost URL on the same network.
* **Tiny surface area.** A few static files and one Python script. Auditable in an afternoon.

## One-click auto-tune

Picking a model in Settings (with a VRAM tier set) automatically runs a tuner that reads the GGUF header for the model's actual architecture — layer count, attention config, MoE expert count, KV head dimensions — and computes the largest context window and the right CPU/GPU offload split for your card. No more hand-picking `--n-cpu-moe`, `--ctx-size`, or `--batch-size`. It picks them, applies them, reloads the model, you chat.

* **GGUF-direct math, not eyeballed.** KV cache cost per token comes from the model's actual `2 × n_layer × head_count_kv × head_dim × dtype_bytes`, not a size bucket. So a Q3 of a given architecture gets *more* context than a Q4 of the same architecture, because the smaller weights file leaves more VRAM free for KV cache.
* **MoE aware.** When the model is mixture-of-experts, the tuner figures out the dense vs expert split and offloads only as many expert layers to CPU as needed to fit, with a 70%-of-layers cap before it nudges you to grab a smaller quant instead. Speculative decoding is auto-disabled because it's net-negative on MoE per public benchmarks.
* **Grow only on context.** If autotune comes back with a smaller number than what you already had working, the larger value wins. Your saved ctx never shrinks behind your back.
* **Self-healing on boot.** Every time the app starts, autotune quietly re-runs in the background and updates flags if the algorithm has improved since you last saved. One toast tells you what changed.
* **Single click, single load.** Picking a model = "do the right thing for this model on my GPU." No separate Suggest step, no Save step, no manual reload.

> **\*Caveat — bigger context is not always better.** Some models will happily autoload very large contexts (200K+ tokens) when their GGUF reports it as supported. The math says it fits in VRAM, but attention itself slows down as the context window grows even before the conversation fills it. If you care more about tokens-per-second than maximum context, **lower the context window manually in Settings** for that specific use case. On a 16 GB card with a small MoE, **32K-65K is usually the sweet spot for sustained 30+ tok/s**. Bigger ctx = more headroom for long documents and conversations; smaller ctx = faster generation. Pick the one that matches what you are actually doing.

## Who this is for

* People who want a Cursor or Antigravity style experience without the subscription
* People who already have a decent GPU and would rather use it than rent one through an API
* Tinkerers who want to swap models around (Qwen, GLM, Llama, Gemma, anything llama.cpp supports) and see what works best for their box
* Privacy people who do not want their drafts, their code, or their thinking sent to a server somewhere
* Anyone who got tired of watching big AI companies decide what their tool is allowed to do this week

## What it is not

* Not a polished commercial product. There are rough edges and the docs are mostly this README.
* Not going to beat Claude Sonnet or GPT 5 on a 24B model running on a laptop. Local is local. Pick the right tool for the job.
* Not a llama.cpp replacement. It is a friendly front end that sits on top of llama-server.
* Not trying to be a code editor. It is a chat workspace that happens to render code, preview HTML, and check Python syntax.

## Privacy

Nothing about you, your prompts, or your files leaves your computer. The bridge talks to two things on localhost: your llama-server instance and your browser. That is it. There is no telemetry, no analytics, no anonymous account, no cloud sync, no opt out screen because there is nothing to opt out of.

The one outbound channel is the agent's own web fetch tool. When the model asks to read a URL, that request goes out from your machine to that site, the same way your browser would. Some models will ask first via an approval card, others will just do it as part of answering your question. Either way nothing is sent unless the model decided it needed something off the open web for the task you gave it.

If you are paranoid (and you should be), run Wireshark next to it. The only outbound traffic you will see is whatever the agent fetched. Want full silence? Run with the network unplugged or block the bridge process at the firewall. The model itself runs offline once loaded, so you can chat all day with no internet at all.

## Quick start

1. Install Python 3.10 or newer.
2. Install dependencies: `pip install -r requirements.txt`
3. Have `llama-server` (or `llama-server.exe` on Windows) somewhere on disk. Use the CUDA build for NVIDIA, the Vulkan build for everything else, or the CPU build if you are brave.
4. Have at least one GGUF model file on disk. Anything llama.cpp can load. A 23B Q4 in the GLM 4.7 family or a Qwen 3 series instruct in the 7B to 32B range is a good starting point on consumer hardware.
5. Double click `start.bat` (Windows) or run `python bridge.py` from the repo root.
6. Open the printed URL in your browser. The default is `http://localhost:8787`.
7. Open Settings, point it at your models folder and llama-server binary, pick a model, and chat.

The first session creates a `data/` folder next to `bridge.py` that holds your chats, settings, workspace pointers, and memories. Back it up if you care about it. Delete it if you want a clean slate.

## Remote access over Tailscale

The bridge listens on your LAN by default, so any device on the same network can already reach it at `http://<your-machine-name>:8787`. Pair that with [Tailscale](https://tailscale.com) and you have your own private AI server reachable from anywhere — laptop in a coffee shop, phone on cellular, friend's couch. Same UI, same model, same conversation history. Nothing leaves your tailnet.

No cloud relay, no port forwarding, no exposing your machine to the open internet. Install Tailscale on the machine running Accuretta and on whatever device you want to chat from, and the URL `http://<machine-name>:8787` (or the tailnet IP) just works. The mobile UI is built for this exact use case — phone browser, no app store, no install. Open the URL and you are in.

A nice side effect: your conversations and your model never round-trip through someone else's data center. The privacy story holds even when you are not at home.

## Repository layout

```
accuretta/
  bridge.py              the Python bridge (model launcher, tool runtime, HTTP server)
  index.html             the UI shell
  app.js                 all UI logic
  app.css                main stylesheet
  colors_and_type.css    theme tokens
  logo-mark.png          the orbital A logo
  start.bat              minimal Windows launcher
  requirements.txt       Python dependencies
  data/                  runtime state, created on first run
  media/                 readme assets (screenshots, demo video)
```

## Status

Personal project. I work on it when I feel like it. Pull requests are welcome but I am not building a roadmap or chasing stars. If you fork it and make it your own, that is the entire point.

## License

MIT. See [LICENSE](LICENSE). Free for personal use. Use it, change it, ship it. The only thing I ask is that you do not pretend you wrote the parts you did not.
