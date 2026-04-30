# Accuretta

A local AI agent and IDE that runs on your own computer. No accounts. No subscriptions. No monthly quota emails. You point it at a model file on your disk and it just works.

## Why I built this

Honestly this started as a side project that came out of a frustration that kept building. I had been paying for various AI subscriptions and watching the goalposts move every few weeks. One company would cut quotas. Another would silently downgrade the model behind the same name. Then Google released Antigravity IDE and I tried it for a while, and that was the moment I got fed up. The whole thing felt like another rented relationship with a tool I was supposed to depend on.

So I started building Accuretta for myself, with two rules:

1. Everything runs locally. The model lives on my disk. The bridge runs on my machine. Nothing leaves the computer unless I explicitly tell it to.
2. No subscriptions. Ever. I already paid for the GPU.

I am very new to llama.cpp. Before this I was an Ollama user and I figured Ollama was the easy way to run local models. After switching to llama.cpp directly through llama-server, the performance jump was bigger than I expected. Same hardware, same model file, noticeably faster generation and cleaner control over things like KV cache quantization, flash attention, and speculative decoding. The tradeoff is that you have to wire it up yourself instead of letting Ollama abstract it away. Accuretta is partly the wiring.

## What it is

A web UI that talks to a Python bridge that talks to llama-server. Drop a .gguf model in a folder, pick it from the dropdown, and you get:

* Chat with tool use. The agent can read and write files, run commands, fetch web pages, and look at screenshots.
* A code preview pane that renders HTML, CSS, and JS as you write.
* Approval cards for anything destructive, so the agent never silently writes a file or runs a script you did not see first.
* Conversation history that lives in a single folder you control.
* A settings drawer where you can change context window, sampler values, KV cache type, and other knobs on the fly with a brief reload.

The whole thing is a few files of HTML, CSS, JS, and one Python file. No build step. No npm. You can open every file and read it in an afternoon.

## Who this is for

* People who want a Cursor or Antigravity style experience without the subscription
* People who already have a decent GPU and would rather use it than rent one through an API
* Tinkerers who want to swap models around (Qwen, Llama, Gemma, anything llama.cpp supports) and see what works best for their box
* Anyone who got tired of watching big AI companies decide what their tool is allowed to do this week

## What it is not

* Not a polished commercial product. There are rough edges.
* Not going to beat Claude or GPT 5 on a 24B model running on a laptop. Local is local. Pick the right tool for the job.
* Not aiming to be a llama.cpp replacement. It is a friendly front end on top of llama-server.

## Use cases

* Writing code with the model right next to a live preview, using your own files as context
* Drafting prose, marketing copy, documentation, anything where you do not want it sent to a server
* Quick agent tasks like "rename these files based on their contents", or "write a small landing page and save it", or "scrape this URL and pull out the prices"
* Spinning up a model briefly to ask a single question without burning an API quota
* Running on an offline machine. Once you have a model downloaded, no internet is required.

## Privacy

Nothing leaves your computer unless you ask it to. The bridge talks to two things on localhost (your llama-server instance, and your browser) and that is it. Web fetches go through an approval card before any request is made. There is no telemetry, no analytics, no anonymous account, no cloud sync.

## Repository layout

This folder is the development checkout. The runtime files are:

* `bridge.py` is the Python bridge. It spawns llama-server, serves the UI, and handles tool calls.
* `index.html`, `app.js`, `app.css`, `colors_and_type.css`, `logo-mark.png` are the web UI.
* `start.bat` is a minimal launcher that assumes Python and dependencies are already installed.
* `data/` is runtime state (chats, settings, workspace, memories). It is created on first run.

For a clean version meant to be moved to another machine, see the `dist` folder if it exists, or grab the matching dist build. It has a smarter `start.bat` that creates a virtual environment and installs dependencies on first run, plus a `requirements.txt` and an end user install guide.

## Quick start (development)

1. Install Python 3.10 or newer.
2. Install dependencies: `pip install requests pillow psutil`
3. Have `llama-server.exe` somewhere on disk. Use the CUDA build for NVIDIA, or the Vulkan build for everything else.
4. Have at least one .gguf model on disk.
5. Double click `start.bat`.
6. Open Settings, point it at your models folder, pick a model, chat.

## Status

Personal project. I work on it when I feel like it. Pull requests welcome but I am not trying to grow a community or build a roadmap. If you fork it and make it your own, that is the whole point.
