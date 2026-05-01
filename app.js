/* ============================================================
   Accuretta frontend — single-file app logic.
   No framework. Vanilla JS. SSE for streaming.
   ============================================================ */
(() => {
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);
  const api = (p, opts) => fetch(p, opts).then(r => r.json());

  // ---------- state ----------
  const state = {
    chats: { chats: {}, order: [] },
    chatId: null,
    messages: [],
    settings: {},
    workspace: { folders: [] },
    models: [],
    mode: "auto",          // auto | ide | agent
    view: "preview",       // preview | code
    versions: [],
    activeVersion: null,   // vid
    currentHtml: "",
    currentFiles: {},      // { "style.css": "...", "script.js": "...", ... } parsed from the current assistant turn
    streaming: false,
    abortCtl: null,
    approvals: new Map(),
    mobileTab: "chat",
    pendingImages: [],  // [{ dataUrl, name }]
    viewport: "full",        // full | desktop | tablet | mobile
    consoleOpen: false,
    consoleLogs: [],         // [{level, text, t}]
    tokTotal: 0,             // cumulative generated tokens for this session (client-side)
    sessionDesktopDisabled: false,
    palette: { open: false, items: [], idx: 0 },
    _versionsExpanded: false,
    _lastMsgTokens: 0,
    _lastMsgPromptTokens: 0,
    _ctxPoll: null,
  };

  const app = $("#app");
  const isMobile = () => window.matchMedia("(max-width: 600px)").matches;

  // ---------- utilities ----------
  // simple toast system — bottom-right, auto-dismiss. keyed toasts replace each other.
  const _toasts = new Map();
  function toast(msg, kind = "info", ms = 3000, key = null) {
    let host = document.getElementById("toast-host");
    if (!host) {
      host = document.createElement("div");
      host.id = "toast-host";
      document.body.appendChild(host);
    }
    if (key && _toasts.has(key)) {
      try { _toasts.get(key).remove(); } catch {}
      _toasts.delete(key);
    }
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.textContent = msg;
    host.appendChild(el);
    if (key) _toasts.set(key, el);
    setTimeout(() => {
      el.classList.add("leaving");
      setTimeout(() => { try { el.remove(); } catch {} if (key && _toasts.get(key) === el) _toasts.delete(key); }, 250);
    }, ms);
    return el;
  }

  const esc = (s) => String(s || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));

  function isNearBottom() {
    const s = $("#chat-scroll");
    return s.scrollHeight - s.scrollTop - s.clientHeight < 120;
  }
  function scrollToBottom(force = false) {
    const s = $("#chat-scroll");
    if (force || isNearBottom()) {
      s.scrollTop = s.scrollHeight;
    }
  }

  function relTime(t) {
    const d = Math.floor(Date.now() / 1000) - (t || 0);
    if (d < 60) return "just now";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  }

  function humanBytes(n) {
    if (n == null) return "—";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1024 / 1024).toFixed(2) + " MB";
  }

  // ---------- tool icons (inlined so no extra HTTP / static-whitelist changes) ----------
  const TOOL_SVG = {
    searching_computer: '<svg viewBox="0 0 150.817 150.817" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><path d="M58.263,64.946c3.58-8.537,9.834-16.039,18.456-21.02c6.644-3.842,14.225-5.876,21.902-5.876c6.376,0,12.568,1.461,18.207,4.031V21.677C116.829,9.706,92.563,0,62.641,0C32.71,0,8.448,9.706,8.448,21.677v21.681C8.436,54.75,30.372,64.061,58.263,64.946z M62.629,5.416c29.77,0,48.768,9.633,48.768,16.255c0,6.634-18.998,16.258-48.768,16.258c-29.776,0-48.774-9.624-48.774-16.258C13.855,15.049,32.853,5.416,62.629,5.416z M8.429,75.883V54.202c0,10.973,20.396,20.015,46.841,21.449c-1.053,7.21-0.311,14.699,2.375,21.799C30.055,96.445,8.436,87.184,8.429,75.883z M95.425,125.631c-9.109,2.771-20.457,4.445-32.796,4.445c-29.931,0-54.193-9.706-54.193-21.684V86.709c0,11.983,24.256,21.684,54.193,21.684c0.341,0,0.673-0.018,1.014-0.018C71.214,118.373,82.827,124.656,95.425,125.631z M131.296,63.11c-10.388-17.987-33.466-24.174-51.46-13.785c-17.987,10.388-24.173,33.463-13.792,51.45c10.388,17.993,33.478,24.174,51.465,13.798C135.51,104.191,141.684,81.102,131.296,63.11z M71.449,97.657C62.778,82.66,67.945,63.394,82.955,54.72c15.01-8.662,34.275-3.504,42.946,11.509c8.672,15.013,3.502,34.279-11.508,42.943C99.377,117.85,80.117,112.686,71.449,97.657z M139.456,133.852l-16.203,9.353l-12.477-21.598l16.209-9.359L139.456,133.852z M137.708,149.562c-4.488,2.582-10.199,1.06-12.794-3.429l16.216-9.353C143.718,141.268,142.184,146.979,137.708,149.562z"/></svg>',
    computer_search_failed: '<svg viewBox="0 0 139.558 139.558" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><path d="M54.19,65.705c29.938,0,54.19-9.703,54.19-21.681V22.344c0-11.977-24.265-21.68-54.19-21.68C24.263,0.664,0,10.367,0,22.344v21.681C0,56.002,24.256,65.705,54.19,65.705z M54.19,6.089c29.773,0,48.771,9.627,48.771,16.255c0,6.628-18.998,16.262-48.771,16.262c-29.772,0-48.771-9.627-48.771-16.255C5.419,15.722,24.418,6.089,54.19,6.089z"/><path d="M54.19,98.225c6.467,0,12.638-0.476,18.39-1.304c4.643-15.381,18.928-26.609,35.801-26.609V54.866c0,11.971-24.265,21.681-54.19,21.681C24.263,76.547,0,66.844,0,54.866v21.681C0,88.518,24.256,98.225,54.19,98.225z"/><path d="M54.19,109.057c-29.934,0-54.19-9.7-54.19-21.678v21.678c0,11.978,24.263,21.684,54.19,21.684c8.306,0,16.148-0.779,23.19-2.107c-3.997-5.906-6.342-13.006-6.394-20.648C65.696,108.673,60.058,109.057,54.19,109.057z"/><path d="M108.381,76.541c-17.214,0-31.176,13.962-31.176,31.176c0,17.215,13.962,31.177,31.176,31.177s31.177-13.962,31.177-31.177C139.558,90.503,125.595,76.541,108.381,76.541z M122.709,115.432l-6.613,6.613l-7.715-7.709l-7.715,7.709l-6.612-6.613l7.708-7.715l-7.708-7.715l6.612-6.613l7.715,7.722l7.715-7.722l6.613,6.613L115,107.717L122.709,115.432z"/></svg>',
    writing_file: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><path d="M17.093,1.293l-11.2,11.2a.99.99,0,0,0-.242.391l-1.6,4.8A1,1,0,0,0,5,19a1.014,1.014,0,0,0,.316-.051l4.8-1.6a1.006,1.006,0,0,0,.391-.242l11.2-11.2a1,1,0,0,0,0-1.414l-3.2-3.2A1,1,0,0,0,17.093,1.293ZM9.26,15.526l-2.679.893.893-2.679L17.8,3.414,19.586,5.2ZM3,21H20a1,1,0,0,1,0,2H3a1,1,0,0,1,0-2Z"/></svg>',
    editing_file: '<svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5.5,9.2H9.2v0H35.1a3.9828,3.9828,0,0,1,3.7,3.7l.1123,20.7359"/><path d="M9.281,13.7433,9.2,35.1a3.9807,3.9807,0,0,0,3.7,3.7H38.8v0h3.7"/><path d="M16.6,31.4V27.7L27.7,16.6l3.7,3.7L20.3,31.4Z"/></svg>',
    deleted: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M10.3094 2.25002H13.6908C13.9072 2.24988 14.0957 2.24976 14.2737 2.27819C14.977 2.39049 15.5856 2.82915 15.9146 3.46084C15.9978 3.62073 16.0573 3.79961 16.1256 4.00494L16.2373 4.33984C16.2562 4.39653 16.2616 4.41258 16.2661 4.42522C16.4413 4.90933 16.8953 5.23659 17.4099 5.24964C17.4235 5.24998 17.44 5.25004 17.5001 5.25004H20.5001C20.9143 5.25004 21.2501 5.58582 21.2501 6.00004C21.2501 6.41425 20.9143 6.75004 20.5001 6.75004H3.5C3.08579 6.75004 2.75 6.41425 2.75 6.00004C2.75 5.58582 3.08579 5.25004 3.5 5.25004H6.50008C6.56013 5.25004 6.5767 5.24998 6.59023 5.24964C7.10488 5.23659 7.55891 4.90936 7.73402 4.42524C7.73863 4.41251 7.74392 4.39681 7.76291 4.33984L7.87452 4.00496C7.94281 3.79964 8.00233 3.62073 8.08559 3.46084C8.41453 2.82915 9.02313 2.39049 9.72643 2.27819C9.90445 2.24976 10.093 2.24988 10.3094 2.25002ZM9.00815 5.25004C9.05966 5.14902 9.10531 5.04404 9.14458 4.93548C9.1565 4.90251 9.1682 4.86742 9.18322 4.82234L9.28302 4.52292C9.37419 4.24941 9.39519 4.19363 9.41601 4.15364C9.52566 3.94307 9.72853 3.79686 9.96296 3.75942C10.0075 3.75231 10.067 3.75004 10.3553 3.75004H13.6448C13.9331 3.75004 13.9927 3.75231 14.0372 3.75942C14.2716 3.79686 14.4745 3.94307 14.5842 4.15364C14.605 4.19363 14.626 4.2494 14.7171 4.52292L14.8169 4.82216L14.8556 4.9355C14.8949 5.04405 14.9405 5.14902 14.992 5.25004H9.00815Z"/><path d="M5.91509 8.45015C5.88754 8.03685 5.53016 7.72415 5.11686 7.7517C4.70357 7.77925 4.39086 8.13663 4.41841 8.54993L4.88186 15.5017C4.96736 16.7844 5.03642 17.8205 5.19839 18.6336C5.36679 19.4789 5.65321 20.185 6.2448 20.7385C6.8364 21.2919 7.55995 21.5308 8.4146 21.6425C9.23662 21.7501 10.275 21.7501 11.5606 21.75H12.4395C13.7251 21.7501 14.7635 21.7501 15.5856 21.6425C16.4402 21.5308 17.1638 21.2919 17.7554 20.7385C18.347 20.185 18.6334 19.4789 18.8018 18.6336C18.9638 17.8206 19.0328 16.7844 19.1183 15.5017L19.5818 8.54993C19.6093 8.13663 19.2966 7.77925 18.8833 7.7517C18.47 7.72415 18.1126 8.03685 18.0851 8.45015L17.6251 15.3493C17.5353 16.6971 17.4713 17.6349 17.3307 18.3406C17.1943 19.025 17.004 19.3873 16.7306 19.6431C16.4572 19.8989 16.083 20.0647 15.391 20.1552C14.6776 20.2485 13.7376 20.25 12.3868 20.25H11.6134C10.2626 20.25 9.32255 20.2485 8.60915 20.1552C7.91715 20.0647 7.54299 19.8989 7.26958 19.6431C6.99617 19.3873 6.80583 19.025 6.66948 18.3406C6.52892 17.6349 6.46489 16.6971 6.37503 15.3493L5.91509 8.45015Z"/><path d="M9.42546 10.2538C9.83762 10.2125 10.2052 10.5133 10.2464 10.9254L10.7464 15.9254C10.7876 16.3376 10.4869 16.7051 10.0747 16.7463C9.66256 16.7875 9.29503 16.4868 9.25381 16.0747L8.75381 11.0747C8.7126 10.6625 9.01331 10.295 9.42546 10.2538Z"/><path d="M14.5747 10.2538C14.9869 10.295 15.2876 10.6625 15.2464 11.0747L14.7464 16.0747C14.7052 16.4868 14.3376 16.7875 13.9255 16.7463C13.5133 16.7051 13.2126 16.3376 13.2538 15.9254L13.7538 10.9254C13.795 10.5133 14.1626 10.2125 14.5747 10.2538Z"/></svg>',
    running_command: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 17H20"/><path d="M5 7L10 12L5 17"/></svg>',
    command_failed: '<svg viewBox="0 0 36 36" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><rect x="17" y="23" width="6" height="2"/><polygon points="7 24.11 16.6 19.7 16.6 17.89 7 13.48 7 15.68 13.79 18.8 7 21.91 7 24.11"/><path d="M33.68,15.4H32V29H4V10.8H18.68A3.66,3.66,0,0,1,19,9.89l.4-.69H4V7H20.71l1.15-2H4A2,2,0,0,0,2,7V29a2,2,0,0,0,2,2H32a2,2,0,0,0,2-2V15.38Z"/><path d="M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z"/></svg>',
    downloading_file: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11C3 11.9319 3 12.3978 3.15224 12.7654C3.35523 13.2554 3.74458 13.6448 4.23463 13.8478C4.60218 14 5.06812 14 6 14H6.67544C7.25646 14 7.54696 14 7.77888 14.1338C7.83745 14.1675 7.89245 14.2072 7.94303 14.2521C8.14326 14.4298 8.23513 14.7054 8.41886 15.2566L8.54415 15.6325C8.76416 16.2925 8.87416 16.6225 9.13605 16.8112C9.39794 17 9.7458 17 10.4415 17H13.5585C14.2542 17 14.6021 17 14.864 16.8112C15.1258 16.6225 15.2358 16.2925 15.4558 15.6325L15.5811 15.2566C15.7649 14.7054 15.8567 14.4298 16.057 14.2521C16.1075 14.2072 16.1625 14.1675 16.2211 14.1338C16.453 14 16.7435 14 17.3246 14H18C18.9319 14 19.3978 14 19.7654 13.8478C20.2554 13.6448 20.6448 13.2554 20.8478 12.7654C21 12.3978 21 11.9319 21 11"/><path d="M8 9L12 12M12 12L16 9M12 12L12 2"/><path d="M16 5H17C18.8856 5 19.8284 5 20.4142 5.58579C21 6.17157 21 7.11438 21 9V17C21 18.8856 21 19.8284 20.4142 20.4142C19.8284 21 18.8856 21 17 21H7C5.11438 21 4.17157 21 3.58579 20.4142C3 19.8284 3 18.8856 3 17V9C3 7.11438 3 6.17157 3.58579 5.58579C4.17157 5 5.11438 5 7 5H8"/></svg>',
    multiple_tasks_complete: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M8.00009 13L12.2278 16.3821C12.6557 16.7245 13.2794 16.6586 13.6264 16.2345L22.0001 6"/><path d="M9.6434 11.5995L14.5356 5.6201"/><path d="M2.36 13.52L4.87309 16.9049C5.559 17.4193 6.52849 17.3016 7.07142 16.638L8.03225 15.4637"/></svg>',
    globe: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
  };
  const TOOL_ICON_MAP = {
    list_directory:  { run: "searching_computer", err: "computer_search_failed" },
    read_file:       { run: "searching_computer", err: "computer_search_failed" },
    grep_files:      { run: "searching_computer", err: "computer_search_failed" },
    write_file:      { run: "writing_file",       err: "command_failed" },
    edit_file:       { run: "editing_file",       err: "command_failed" },
    patch_file:      { run: "editing_file",       err: "command_failed" },
    delete_file:     { run: "deleted",            err: "command_failed" },
    run_powershell:  { run: "running_command",    err: "command_failed" },
    open_program:    { run: "running_command",    err: "command_failed" },
    web_fetch:       { run: "downloading_file",   err: "command_failed" },
    web_search:      { run: "globe",              err: "computer_search_failed" },
    network_snapshot:{ run: "globe",              err: "computer_search_failed" },
  };
  function renderWebSearchChips(results) {
    if (!results || !results.length) return "";
    const max = 4;
    const visible = results.slice(0, max);
    const overflow = results.length - visible.length;
    const chips = visible.map(r => {
      let host = "";
      try { host = new URL(r.url).hostname.replace(/^www\./, ""); } catch {}
      const label = host || r.url;
      const fav = host ? `https://icons.duckduckgo.com/ip3/${host}.ico` : "";
      // Wrap: globe fallback always rendered; img sits on top, hides itself on error.
      const favHtml = `<span class="web-fav-wrap">${TOOL_SVG.globe}${fav ? `<img class="web-fav" src="${esc(fav)}" alt="" loading="lazy" onerror="this.style.display='none'">` : ""}</span>`;
      return `<a class="web-chip" href="${esc(r.url)}" target="_blank" rel="noopener noreferrer" title="${esc(r.title || r.url)}">${favHtml}<span>${esc(label)}</span></a>`;
    }).join("");
    const moreChip = overflow > 0
      ? `<span class="web-chip web-chip-more">+${overflow} more</span>`
      : "";
    return `<div class="web-results">${chips}${moreChip}</div>`;
  }

  function renderNetworkChart(res) {
    if (!res || res.error) return "";
    const tcp = res.tcp_count || 0;
    const udp = res.udp_count || 0;
    const dns = (res.recent_dns || []).length;
    const procs = (res.top_processes || []).slice(0, 6);
    const remotes = (res.top_remotes || []).slice(0, 6);
    const procMax = procs.reduce((m, p) => Math.max(m, p.connections || 0), 1);
    const remMax = remotes.reduce((m, r) => Math.max(m, r.count || 0), 1);
    const stat = (label, n, cls) => `<div class="net-stat ${cls}"><div class="net-stat-num">${n}</div><div class="net-stat-lbl">${label}</div></div>`;
    const procRow = (p) => {
      const w = Math.max(4, Math.round(((p.connections || 0) / procMax) * 100));
      return `<div class="net-bar-row"><span class="net-bar-lbl" title="${esc(p.process || "?")}">${esc(p.process || "?")}</span><span class="net-bar-track"><span class="net-bar-fill net-bar-proc" style="width:${w}%"></span></span><span class="net-bar-num">${p.connections || 0}</span></div>`;
    };
    const remRow = (r) => {
      const w = Math.max(4, Math.round(((r.count || 0) / remMax) * 100));
      const lbl = `${r.address || "?"}${r.port ? ":" + r.port : ""}`;
      return `<div class="net-bar-row"><span class="net-bar-lbl" title="${esc(lbl)}">${esc(lbl)}</span><span class="net-bar-track"><span class="net-bar-fill net-bar-rem" style="width:${w}%"></span></span><span class="net-bar-num">${r.count || 0}</span></div>`;
    };
    const procBlock = procs.length
      ? `<div class="net-block"><div class="net-block-title">Top processes</div>${procs.map(procRow).join("")}</div>`
      : "";
    const remBlock = remotes.length
      ? `<div class="net-block"><div class="net-block-title">Top remote endpoints</div>${remotes.map(remRow).join("")}</div>`
      : "";
    return `<div class="netscan-card">
      <div class="net-stats">${stat("TCP", tcp, "net-stat-tcp")}${stat("UDP", udp, "net-stat-udp")}${stat("DNS", dns, "net-stat-dns")}</div>
      ${procBlock}${remBlock}
    </div>`;
  }

  function toolIconHtml(name, kind /* "run" | "done" | "err" */) {
    const map = TOOL_ICON_MAP[name];
    if (!map) return null;
    const which = kind === "err" ? map.err : map.run;
    const svg = TOOL_SVG[which];
    if (!svg) return null;
    const cls = `tool-svg ${kind === "run" ? "breathing" : kind === "err" ? "is-err" : "is-done"}`;
    return `<span class="${cls}">${svg}</span>`;
  }

  // ---------- friendly tool call labels ----------
  function shortPath(p) {
    if (!p) return "";
    const s = String(p).replace(/\\/g, "/");
    const parts = s.split("/").filter(Boolean);
    return parts.length <= 2 ? s : "…/" + parts.slice(-2).join("/");
  }
  // Tools whose action the user almost always wants to see in full (paths,
  // commands). Everything else (reads, searches, listings, memory ops) gets
  // collapsed into a single chevron group to keep the chat readable.
  const COMMAND_TOOLS = new Set([
    "write_file", "delete_file", "edit_file", "patch_file",
    "run_powershell", "open_program",
    "desktop_launch_app", "desktop_focus_window", "desktop_click",
    "desktop_type_text", "desktop_press_keys", "desktop_close_window",
  ]);
  // Tools whose result is the point — collapsing them defeats the purpose.
  // web_search renders a chip row of sources that the user clicks through; it
  // must stay visible after the run finishes, not get folded into the wrench.
  const ALWAYS_INLINE_TOOLS = new Set(["web_search", "network_snapshot"]);
  function isCommandTool(name) { return COMMAND_TOOLS.has(name); }
  function isInlineTool(name) { return COMMAND_TOOLS.has(name) || ALWAYS_INLINE_TOOLS.has(name); }

  function getOrCreateToolGroup(stack) {
    let group = stack.querySelector(".tool-group:last-of-type");
    // start a new group if the previous one already finished (no .running cards)
    if (group && !group.querySelector(".tool-line.running") && group.dataset.sealed === "1") {
      group = null;
    }
    if (group) return { group, body: group.querySelector(".tool-group-body") };
    group = document.createElement("div");
    group.className = "tool-group collapsed";
    group.innerHTML = `
      <div class="tool-group-head">
        <i class="ph ph-wrench tool-icon spinning"></i>
        <span class="tool-group-label">working…</span>
        <i class="ph ph-caret-down chevron"></i>
      </div>
      <div class="tool-group-body"></div>`;
    const head = group.querySelector(".tool-group-head");
    head.addEventListener("click", () => group.classList.toggle("collapsed"));
    stack.appendChild(group);
    return { group, body: group.querySelector(".tool-group-body") };
  }

  function updateToolGroupHead(stack) {
    const groups = stack.querySelectorAll(".tool-group");
    for (const g of groups) {
      const cards = g.querySelectorAll(".tool-line");
      const running = g.querySelectorAll(".tool-line.running").length;
      const done = g.querySelectorAll(".tool-line.done").length;
      const err = g.querySelectorAll(".tool-line.err").length;
      const total = cards.length;
      const icon = g.querySelector(".tool-icon");
      const label = g.querySelector(".tool-group-label");
      if (running > 0) {
        icon?.classList.add("spinning");
        if (label) label.textContent = `working…`;
      } else {
        icon?.classList.remove("spinning");
        g.dataset.sealed = "1";
        const summary = err > 0
          ? `${done} step${done === 1 ? "" : "s"} · ${err} failed`
          : `${done} step${done === 1 ? "" : "s"}`;
        if (label) label.textContent = summary;
      }
    }
  }

  function toolLabel(name, args) {
    args = args || {};
    switch (name) {
      case "list_directory": return `Looking in ${shortPath(args.path) || "folder"}…`;
      case "read_file":      return `Reading ${shortPath(args.path)}…`;
      case "write_file":     return `Writing ${shortPath(args.path)}…`;
      case "edit_file":      return `Editing ${shortPath(args.path)}…`;
      case "delete_file":    return `Deleting ${shortPath(args.path)}…`;
      case "run_powershell": return `Running command…`;
      case "open_program":   return `Opening ${args.name || args.path || "program"}…`;
      case "web_fetch":      return `Fetching ${args.url || "the web"}…`;
      case "network_snapshot": return `Scanning network…`;
      default:               return `Running ${name || "tool"}…`;
    }
  }
  function toolResultLabel(name, res) {
    res = res || {};
    if (res.error) return `${name}: ${String(res.error).slice(0, 120)}`;
    switch (name) {
      case "list_directory": {
        const n = (res.entries || []).length;
        return `Found ${n} item${n === 1 ? "" : "s"}${res.path ? " in " + shortPath(res.path) : ""}`;
      }
      case "read_file":      return `Read ${shortPath(res.path)}${res.bytes != null ? ` (${res.bytes} bytes)` : ""}`;
      case "write_file":     return `Wrote ${shortPath(res.path)}`;
      case "edit_file":      return `Edited ${shortPath(res.path)} · ${res.edits_applied || 0} change${(res.edits_applied || 0) === 1 ? "" : "s"}`;
      case "delete_file":    return `Deleted ${shortPath(res.path)}`;
      case "run_powershell": {
        const out = (res.stdout || "").trim();
        const first = out.split(/\r?\n/)[0] || "(no output)";
        return `Done · ${first.slice(0, 120)}`;
      }
      case "open_program":   return `Opened ${res.name || ""}`;
      case "web_fetch":      return `Fetched ${shortPath(res.url)}`;
      case "network_snapshot": {
        const t = res.tcp_count || 0;
        const u = res.udp_count || 0;
        const d = (res.recent_dns || []).length;
        return `Scan: ${t} TCP · ${u} UDP · ${d} DNS entries`;
      }
      default:               return `${name} complete`;
    }
  }

  // ---------- markdown-lite for chat bubbles ----------
  // Preserves code fences, ignores tool_call tags (rendered as tool cards separately).
  function renderMarkdown(text) {
    if (!text) return "";

    // === STRIP ALL TOOL CALL FORMATS ===
    // Closed forms — the parser already executed these; just clean the bubble.
    text = text.replace(/<tool_call>[\s\S]*?<\/tool_call>/gi, "");
    text = text.replace(/```tool_call[\s\S]*?```/gi, "");
    // BugTraceAI / gemma-tunes:  <call:NAME>{...}</call(:NAME)?>
    text = text.replace(/<call:[a-zA-Z0-9_\-]+>[\s\S]*?<\/call(?::[a-zA-Z0-9_\-]+)?>/gi, "");
    // Llama 3.x native:  <|python_tag|>{...}(<|eom_id|>|<|eot_id|>)
    text = text.replace(/<\|python_tag\|>[\s\S]*?(<\|eom_id\|>|<\|eot_id\|>)/gi, "");
    // Mistral native:  [TOOL_CALLS][{...}]
    text = text.replace(/\[TOOL_CALLS\]\s*\[[\s\S]*?\]/gi, "");
    // Partial / streaming open-only forms — the closer hasn't arrived yet,
    // so the regex above can't catch them and the user sees raw tag spam
    // flicker mid-stream. Strip from the open tag to end-of-text.
    text = text.replace(/<tool_call>[\s\S]*$/gi, "");
    text = text.replace(/<call:[a-zA-Z0-9_\-]+>[\s\S]*$/gi, "");
    text = text.replace(/<\|python_tag\|>[\s\S]*$/gi, "");
    text = text.replace(/\[TOOL_CALLS\][\s\S]*$/gi, "");
    text = text.replace(/```tool_call[\s\S]*$/gi, "");
    text = text.replace(/```json\s*\{[\s\S]*?"name"[\s\S]*?\}\s*```/gi, "");
    text = text.replace(/```json\s*\{[\s\S]*?"function"[\s\S]*?\}\s*```/gi, "");
    text = text.replace(/<function_calls>[\s\S]*?<\/function_calls>/gi, "");
    text = text.replace(/<functions>[\s\S]*?<\/functions>/gi, "");
    text = text.replace(/<invoke>[\s\S]*?<\/invoke>/gi, "");
    text = text.replace(/<tool>[\s\S]*?<\/tool>/gi, "");
    text = text.replace(/\{\s*"name"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:\s*\{[\s\S]*?\}\s*\}/g, "");
    text = text.replace(/\[[\s\S]*?\{[\s\S]*?"name"[\s\S]*?"arguments"[\s\S]*?\}[\s\S]*?\]/g, "");
    text = text.replace(/\*\*Tool call:.*?\*\*/gi, "");
    text = text.replace(/\*\*Function call:.*?\*\*/gi, "");
    text = text.replace(/Calling\s+\w+\s*\(.*?\)\s*\.\.\./gi, "");
    text = text.replace(/\[\s*\d+\s*tool\s*calls?\s*\]/gi, "");
    text = text.replace(/\n{3,}/g, "\n\n");
    text = text.trim();

    // extract code fences
    const fences = [];
    text = text.replace(/```(\w+)?\n?([\s\S]*?)```/g, (_m, lang, code) => {
      fences.push({ lang: lang || "", code });
      return `\x00F${fences.length - 1}\x00`;
    });

    let escaped = esc(text);

    // --- block-level passes (work on escaped text, line-by-line) ---
    const lines = escaped.split("\n");
    const blocks = [];
    let i2 = 0;
    while (i2 < lines.length) {
      const ln = lines[i2];
      // pipe table: header row + separator (| --- | --- |) + body rows
      if (/^\s*\|.*\|\s*$/.test(ln) && i2 + 1 < lines.length && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/.test(lines[i2 + 1])) {
        const headerCells = ln.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim());
        const sepCells = lines[i2 + 1].trim().replace(/^\||\|$/g, "").split("|");
        const aligns = sepCells.map(c => {
          const t = c.trim();
          if (t.startsWith(":") && t.endsWith(":")) return "center";
          if (t.endsWith(":")) return "right";
          return "left";
        });
        const rows = [];
        let j = i2 + 2;
        while (j < lines.length && /^\s*\|.*\|\s*$/.test(lines[j])) {
          rows.push(lines[j].trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim()));
          j++;
        }
        const inline = (s) => s
          .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
          .replace(/\*([^*]+)\*/g, "<em>$1</em>")
          .replace(/`([^`]+)`/g, "<code>$1</code>");
        const thead = "<thead><tr>" + headerCells.map((c, k) => `<th style="text-align:${aligns[k] || "left"}">${inline(c)}</th>`).join("") + "</tr></thead>";
        const tbody = "<tbody>" + rows.map(r => "<tr>" + r.map((c, k) => `<td style="text-align:${aligns[k] || "left"}">${inline(c)}</td>`).join("") + "</tr>").join("") + "</tbody>";
        blocks.push(`<table class="md-table">${thead}${tbody}</table>`);
        i2 = j;
        continue;
      }
      // ATX headings
      const h = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(ln);
      if (h) {
        const lvl = h[1].length;
        blocks.push(`<h${lvl} class="md-h${lvl}">${h[2]}</h${lvl}>`);
        i2++;
        continue;
      }
      // horizontal rule
      if (/^\s*(---|\*\*\*|___)\s*$/.test(ln)) {
        blocks.push(`<hr class="md-hr">`);
        i2++;
        continue;
      }
      // unordered list
      if (/^\s*[-*]\s+/.test(ln)) {
        const items = [];
        while (i2 < lines.length && /^\s*[-*]\s+/.test(lines[i2])) {
          items.push(lines[i2].replace(/^\s*[-*]\s+/, ""));
          i2++;
        }
        blocks.push("<ul class=\"md-list\">" + items.map(t => `<li>${t}</li>`).join("") + "</ul>");
        continue;
      }
      // ordered list
      if (/^\s*\d+\.\s+/.test(ln)) {
        const items = [];
        while (i2 < lines.length && /^\s*\d+\.\s+/.test(lines[i2])) {
          items.push(lines[i2].replace(/^\s*\d+\.\s+/, ""));
          i2++;
        }
        blocks.push("<ol class=\"md-list\">" + items.map(t => `<li>${t}</li>`).join("") + "</ol>");
        continue;
      }
      // accumulate paragraph lines until blank
      const para = [];
      while (i2 < lines.length && lines[i2].trim() !== "" &&
             !/^\s*\|.*\|\s*$/.test(lines[i2]) &&
             !/^#{1,6}\s+/.test(lines[i2]) &&
             !/^\s*(---|\*\*\*|___)\s*$/.test(lines[i2]) &&
             !/^\s*[-*]\s+/.test(lines[i2]) &&
             !/^\s*\d+\.\s+/.test(lines[i2])) {
        para.push(lines[i2]);
        i2++;
      }
      if (para.length) {
        blocks.push("<p>" + para.join("<br>") + "</p>");
      } else {
        i2++;
      }
    }

    let out = blocks.join("")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*]+)\*/g, "<em>$1</em>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");

    out = out.replace(/\x00F(\d+)\x00/g, (_, i) => {
      const { lang, code } = fences[+i];
      return `<pre data-lang="${esc(lang)}"><code>${esc(code)}</code></pre>`;
    });
    return out;
  }

  // very small HTML syntax highlighter for code view
  function highlightHTML(src) {
    const s = esc(src);
    return s
      .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="tok-comment">$1</span>')
      .replace(/(&lt;\/?)([a-zA-Z][\w-]*)/g, '$1<span class="tok-tag">$2</span>')
      .replace(/(\s)([a-zA-Z][\w-]*)=(&quot;[^&]*?&quot;)/g, '$1<span class="tok-attr">$2</span>=<span class="tok-str">$3</span>');
  }

  // ---------- bootstrap ----------
  async function boot() {
    // on-device hint
    if (isMobile()) document.body.classList.add("is-mobile");

    await Promise.all([
      loadSettings(),
      loadWorkspace(),
      loadChats(),
      loadModels(),
    ]);

    // pick or create current chat
    if (state.chats.order.length) {
      selectChat(state.chats.order[0]);
    } else {
      await newChat();
    }

    applyTheme(state.settings.theme === "dark");
    renderStatus();
    renderModelPill();
    renderChatList();
    renderWorkspace();
    reflectIdeToggles();

    wireEvents();
    subscribeSSE();
  }

  function reflectIdeToggles() {
    const tw = $("#toggle-tailwind");
    if (tw) tw.classList.toggle("on", !!state.settings.use_tailwind_cdn);
    const mf = $("#toggle-multifile");
    if (mf) mf.classList.toggle("on", !!state.settings.ide_multifile);
  }

  // ---------- data loading ----------
  async function loadSettings() {
    state.settings = await api("/api/settings");
  }
  async function saveSettings(update) {
    const prevModel = state.settings.model;
    state.settings = await api("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(update),
    });
    // model changed mid-stream → abort so next send uses fresh model cleanly
    if (update.model && update.model !== prevModel && state.streaming) {
      stopStreaming();
    }
    renderStatus();
    renderModelPill();
  }
  async function loadWorkspace() {
    state.workspace = await api("/api/workspace");
  }
  async function loadChats() {
    state.chats = await api("/api/chats");
  }
  async function loadModels() {
    try {
      const r = await api("/api/models");
      state.modelsDir = r.models_dir || "";
      state.loadedModel = r.loaded_model || "";
      state.llamaRunning = !!r.llama_running;
      state.modelsList = Array.isArray(r.models) ? r.models : [];
      state.models = state.modelsList.map(m => m.name).filter(Boolean);
      if (r.error) state.modelsError = r.error;
      else if (!state.modelsDir) state.modelsError = "no models folder set — pick one above.";
      else if (!state.models.length) state.modelsError = "no .gguf files found in " + state.modelsDir;
      else state.modelsError = "";
    } catch (e) {
      state.models = [];
      state.modelsList = [];
      state.modelsError = "bridge unreachable: " + (e.message || e);
    }
  }

  // ---------- chat ----------
  async function newChat() {
    const c = await api("/api/chats", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "new session" }),
    });
    await loadChats();
    selectChat(c.id);
    const ta = $("#composer-input");
    ta.value = "";
    autoResize(ta);
  }

  function selectChat(id) {
    state.chatId = id;
    const chat = state.chats.chats[id];
    // Only render visible bubbles. The chat record now also stores
    // intermediate assistant turns (with tool_calls) and tool-result messages
    // so the bridge can replay the full agentic working memory on the next
    // turn — but those aren't bubbles, the renderer skips them.
    state.messages = chat
      ? (chat.messages || []).filter(
          m => (m.role === "user" || m.role === "assistant") && !m._internal
        )
      : [];
    $("#chat-title").textContent = chat ? chat.title : "new session";
    // restore the last-used mode for this chat so the toolbar feels sticky
    if (chat && chat.last_mode && ["auto", "ide", "agent"].includes(chat.last_mode)) {
      state.mode = chat.last_mode;
      $$('[data-mode]').forEach(x => x.classList.toggle("on", x.dataset.mode === state.mode));
    }
    // reset cumulative token counter when switching chats — it tracks the live
    // session, not historical usage
    state.tokTotal = 0;
    renderTokTotal();
    refreshSessionDesktopState();
    renderMessages();
    state._versionsExpanded = false;
    loadVersions();
    renderChatList();
    // restore composer draft
    const ta = $("#composer-input");
    ta.value = localStorage.getItem("accuretta:draft:" + id) || "";
    autoResize(ta);
    if (isMobile()) {
      state.mobileTab = "chat";
      applyMobileTab();
    }
    // start context-stats polling
    clearInterval(state._ctxPoll);
    state._ctxPoll = setInterval(async () => {
      try {
        const r = await api("/api/ctx-stats");
        if (r && typeof r.prompt_tokens === "number") {
          state._lastMsgPromptTokens = r.prompt_tokens;
          renderCtxGauge();
        }
      } catch (_) {}
    }, 2000);
  }

  // ---------- session-scoped desktop kill switch ----------
  async function refreshSessionDesktopState() {
    const btn = $("#btn-session-desktop");
    if (!btn) return;
    if (!state.chatId || !state.settings.desktop_enabled) {
      btn.hidden = true;
      return;
    }
    btn.hidden = false;
    try {
      const r = await fetch(`/api/desktop/chat-state/${state.chatId}`).then(x => x.json());
      state.sessionDesktopDisabled = !!r.disabled;
    } catch { state.sessionDesktopDisabled = false; }
    btn.classList.toggle("off", state.sessionDesktopDisabled);
    btn.title = state.sessionDesktopDisabled
      ? "Desktop automation OFF for this chat — click to re-enable"
      : "Desktop automation ON for this chat — click to disable";
    btn.innerHTML = state.sessionDesktopDisabled
      ? '<i class="ph ph-monitor-x"></i>'
      : '<i class="ph ph-desktop"></i>';
  }

  async function toggleSessionDesktop() {
    if (!state.chatId) return;
    const next = !state.sessionDesktopDisabled;
    try {
      await fetch("/api/desktop/chat-toggle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: state.chatId, disabled: next }),
      });
      state.sessionDesktopDisabled = next;
      refreshSessionDesktopState();
      toast(next ? "Desktop off for this chat" : "Desktop on for this chat", "info", 2200, "sess-desk");
    } catch (e) {
      toast("Toggle failed: " + e.message, "err", 2800);
    }
  }

  async function deleteChat(id) {
    if (!confirm("Delete this session and its versions?")) return;
    await fetch(`/api/chats/${id}`, { method: "DELETE" });
    localStorage.removeItem("accuretta:draft:" + id);
    await loadChats();
    if (state.chatId === id) {
      if (state.chats.order.length) selectChat(state.chats.order[0]);
      else await newChat();
    } else {
      renderChatList();
    }
  }

  // ---------- command palette (⌘K) ----------
  function openPalette() {
    state.palette.open = true;
    state.palette.idx = 0;
    $("#palette-scrim").classList.remove("hidden");
    $("#palette").classList.remove("hidden");
    const inp = $("#palette-input");
    inp.value = "";
    refreshPaletteList("");
    setTimeout(() => inp.focus(), 0);
  }
  function closePalette() {
    state.palette.open = false;
    $("#palette-scrim").classList.add("hidden");
    $("#palette").classList.add("hidden");
  }
  function _fuzzyScore(query, text) {
    if (!query) return 0;
    const q = query.toLowerCase();
    const t = (text || "").toLowerCase();
    if (t.includes(q)) return 100 - t.indexOf(q);
    // cheap subsequence scoring: every char of q must appear in order
    let i = 0, score = 0, last = -1;
    for (let j = 0; j < t.length && i < q.length; j++) {
      if (t[j] === q[i]) { score += 5 - Math.min(4, j - last - 1); last = j; i++; }
    }
    return i === q.length ? score : -1;
  }
  function refreshPaletteList(query) {
    const list = $("#palette-list");
    list.innerHTML = "";
    const items = [];
    // built-in commands always appear first
    const commands = [
      { kind: "cmd", icon: "ph-plus", label: "New session", action: () => { closePalette(); newChat(); } },
      { kind: "cmd", icon: "ph-gear-six", label: "Open Settings", action: () => { closePalette(); openSettings(); } },
      { kind: "cmd", icon: "ph-brain", label: "Open Memories", action: () => { closePalette(); openSettings(); setTimeout(() => $("#btn-mem-refresh")?.scrollIntoView({ behavior: "smooth" }), 80); } },
      { kind: "cmd", icon: "ph-arrow-counter-clockwise", label: "Regenerate last reply", action: () => { closePalette(); regenerateLast(); } },
      { kind: "cmd", icon: "ph-moon", label: "Toggle theme", action: async () => { closePalette(); const d = state.settings.theme !== "dark"; await saveSettings({ theme: d ? "dark" : "light" }); applyTheme(d); } },
      { kind: "cmd", icon: "ph-browser", label: "Toggle preview pane", action: () => { closePalette(); app.classList.toggle("preview-collapsed"); } },
      { kind: "cmd", icon: "ph-camera", label: "Screenshot preview", action: () => { closePalette(); screenshotPreview(); } },
      { kind: "cmd", icon: "ph-package", label: "Export project", action: () => { closePalette(); exportProjectZip(); } },
      { kind: "cmd", icon: "ph-floppy-disk", label: "Save snapshot", action: () => { closePalette(); saveSnapshot(); } },
    ];
    for (const c of commands) {
      const s = query ? _fuzzyScore(query, c.label) : 0;
      if (query && s < 0) continue;
      items.push({ ...c, score: s + 50 });
    }
    // then sessions
    for (const id of state.chats.order) {
      const c = state.chats.chats[id];
      if (!c) continue;
      const label = c.title || "(untitled)";
      const s = query ? _fuzzyScore(query, label) : 0;
      if (query && s < 0) continue;
      items.push({
        kind: "session",
        icon: "ph-chat-circle",
        label,
        sub: id === state.chatId ? "current" : relTime(c.updated || c.created),
        action: () => { closePalette(); selectChat(id); },
        score: s,
      });
    }
    items.sort((a, b) => b.score - a.score);
    state.palette.items = items;
    state.palette.idx = 0;
    items.forEach((it, i) => {
      const el = document.createElement("div");
      el.className = "palette-item" + (i === 0 ? " sel" : "");
      el.innerHTML = `
        <i class="ph ${it.icon}"></i>
        <div class="pi-main">
          <div class="pi-label">${esc(it.label)}</div>
          ${it.sub ? `<div class="pi-sub">${esc(it.sub)}</div>` : ""}
        </div>
        <span class="pi-kind">${esc(it.kind)}</span>`;
      el.addEventListener("click", it.action);
      list.appendChild(el);
    });
    if (!items.length) {
      list.innerHTML = `<div class="palette-empty">no matches.</div>`;
    }
  }
  function paletteMove(delta) {
    const items = state.palette.items;
    if (!items.length) return;
    state.palette.idx = (state.palette.idx + delta + items.length) % items.length;
    const rows = document.querySelectorAll("#palette-list .palette-item");
    rows.forEach((r, i) => r.classList.toggle("sel", i === state.palette.idx));
    const r = rows[state.palette.idx];
    if (r) r.scrollIntoView({ block: "nearest" });
  }
  function paletteCommit() {
    const it = state.palette.items[state.palette.idx];
    if (it) it.action();
  }

  function renderChatList() {
    const wrap = $("#chatlist");
    wrap.innerHTML = "";
    for (const id of state.chats.order) {
      const c = state.chats.chats[id];
      if (!c) continue;
      const row = document.createElement("div");
      row.className = "chatrow" + (id === state.chatId ? " active" : "");
      row.innerHTML = `
        <i class="ph ph-chat-circle"></i>
        <span class="t">${esc(c.title)}</span>
        <span class="d">${relTime(c.updated)}</span>
        <button class="del" title="Delete"><i class="ph ph-trash"></i></button>`;
      row.addEventListener("click", (e) => {
        if (e.target.closest(".del")) return;
        selectChat(id);
      });
      row.querySelector(".del").addEventListener("click", (e) => {
        e.stopPropagation();
        deleteChat(id);
      });
      wrap.appendChild(row);
    }
  }

  function renderMessages() {
    const inner = $("#chat-inner");
    inner.innerHTML = "";
    if (!state.messages.length) {
      inner.innerHTML = `
        <div class="bubble-row">
          <div class="avatar"><i class="ph-bold ph-sparkle" style="font-size:12px"></i></div>
          <div class="bubble-col">
            <div class="bubble agent">Welcome to Accuretta. What would you like to do today?</div>
          </div>
        </div>`;
      scrollToBottom(true);
      return;
    }
    for (const m of state.messages) {
      inner.appendChild(renderBubble(m));
    }
    renderRegenerateChip();
    scrollToBottom(true);
  }

  function renderBubble(m) {
    const row = document.createElement("div");
    row.className = "bubble-row " + (m.role === "user" ? "user" : "");
    const avatar = m.role === "user"
      ? `<div class="avatar user">me</div>`
      : `<div class="avatar"><i class="ph-bold ph-sparkle" style="font-size:12px"></i></div>`;

    let visible = m.content || "";
    let thoughtChip = "";
    if (m.role === "assistant") {
      const { thinking, content } = splitThinking(visible);
      visible = content;
      if (thinking) {
        thoughtChip = `<div class="think-line done" data-thinking="${esc(thinking)}"><i class="ph ph-check"></i><span>Thought for a moment</span></div>`;
      }
    }

    const tokTip = m.tokens ? ` title="${m.tokens.toLocaleString()} tokens"` : "";
    row.innerHTML = `
      ${avatar}
      <div class="bubble-col">
        ${thoughtChip}
        <div class="bubble ${m.role === "user" ? "user" : "agent"}">${renderMarkdown(visible)}</div>
        <div class="bubble-meta"${tokTip}>${m.role === "user" ? "you" : (state.settings.model || "agent")} · ${relTime(m.t)}</div>
      </div>`;
    // copy button for every bubble
    const copyBtn = document.createElement("button");
    copyBtn.className = "copy-msg";
    copyBtn.type = "button";
    copyBtn.innerHTML = '<i class="ph ph-copy"></i>';
    copyBtn.title = "Copy message";
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(m.content || "");
        copyBtn.innerHTML = '<i class="ph ph-check"></i>';
        setTimeout(() => (copyBtn.innerHTML = '<i class="ph ph-copy"></i>'), 1200);
      } catch {
        toast("Clipboard blocked", "warn", 2000);
      }
    });
    row.querySelector(".bubble-col").appendChild(copyBtn);
    enhanceCodeBlocks(row);
    return row;
  }

  // wrap each <pre><code> in the bubble with a copy button. idempotent —
  // bails out if the pre already carries data-enhanced.
  function enhanceCodeBlocks(root) {
    const pres = root.querySelectorAll("pre");
    pres.forEach(pre => {
      if (pre.dataset.enhanced === "1") return;
      pre.dataset.enhanced = "1";
      pre.classList.add("code-block");
      const btn = document.createElement("button");
      btn.className = "copy-code";
      btn.type = "button";
      btn.innerHTML = '<i class="ph ph-copy"></i>';
      btn.title = "Copy";
      btn.addEventListener("click", async () => {
        const codeEl = pre.querySelector("code");
        const text = codeEl ? codeEl.textContent : pre.textContent;
        try {
          await navigator.clipboard.writeText(text || "");
          btn.innerHTML = '<i class="ph ph-check"></i>';
          setTimeout(() => (btn.innerHTML = '<i class="ph ph-copy"></i>'), 1200);
        } catch {
          toast("Clipboard blocked", "warn", 2000);
        }
      });
      pre.appendChild(btn);
    });
  }

  // regenerate the most recent assistant reply by re-sending the turn with
  // regenerate:true.  the backend pops trailing assistant messages and
  // replays the last user message through the same pipeline.
  async function regenerateLast() {
    if (state.streaming) return;
    if (!state.messages.some(m => m.role === "assistant")) {
      toast("Nothing to regenerate yet.", "warn", 2200);
      return;
    }
    // drop the last assistant bubble visually before re-streaming
    while (state.messages.length && state.messages[state.messages.length - 1].role === "assistant") {
      state.messages.pop();
    }
    renderMessages();

    const agentRow = document.createElement("div");
    agentRow.className = "bubble-row";
    agentRow.innerHTML = `
      <div class="avatar"><i class="ph-bold ph-sparkle" style="font-size:12px"></i></div>
      <div class="bubble-col">
        <div class="think-line" data-label="Thinking"><i class="ph ph-brain"></i><span class="shimmer">Regenerating…</span></div>
        <div class="tool-stack" id="tool-stack"></div>
        <div class="bubble agent hidden" id="stream-bubble"></div>
        <div class="bubble-meta streaming">${esc(state.settings.model)} · streaming<span class="typing"><span></span><span></span><span></span></span></div>
      </div>`;
    $("#chat-inner").appendChild(agentRow);
    scrollToBottom(true);

    state.streaming = true;
    state.abortCtl = new AbortController();
    setStreamingUI(true);
    try {
      await streamChat("", agentRow, state.abortCtl.signal, [], { regenerate: true });
    } catch (e) {
      if (e.name !== "AbortError") toast("regenerate failed: " + e.message, "err");
    } finally {
      state.streaming = false;
      state.abortCtl = null;
      setStreamingUI(false);
      renderRegenerateChip();
    }
  }

  // show an action row (regenerate + copy) under the last assistant bubble.
  function renderRegenerateChip() {
    const existing = document.querySelector(".bubble-actions");
    if (existing) existing.remove();
    const rows = [...document.querySelectorAll("#chat-inner .bubble-row")];
    const lastAssistant = rows.reverse().find(r => r.querySelector(".bubble.agent"));
    if (!lastAssistant) return;
    const col = lastAssistant.querySelector(".bubble-col");
    if (!col) return;
    const meta = col.querySelector(".bubble-meta");
    if (!meta) return;
    const bubble = col.querySelector(".bubble.agent");
    const actions = document.createElement("div");
    actions.className = "bubble-actions";
    actions.innerHTML = `
      <button type="button" class="bubble-action" data-act="regen" title="Regenerate"><i class="ph ph-arrow-counter-clockwise"></i></button>
      <button type="button" class="bubble-action" data-act="copy" title="Copy"><i class="ph ph-copy"></i></button>
    `;
    actions.querySelector('[data-act="regen"]').addEventListener("click", regenerateLast);
    actions.querySelector('[data-act="copy"]').addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      const text = bubble?.innerText || "";
      try {
        await navigator.clipboard.writeText(text);
        const icon = btn.querySelector("i");
        if (icon) {
          icon.classList.remove("ph-copy");
          icon.classList.add("ph-check");
          btn.classList.add("copied");
          setTimeout(() => {
            icon.classList.remove("ph-check");
            icon.classList.add("ph-copy");
            btn.classList.remove("copied");
          }, 1400);
        }
      } catch {
        toast("copy failed", "err", 2000);
      }
    });
    meta.after(actions);
  }

  // ---------- image attachments ----------
  function renderImageTray() {
    const tray = $("#image-tray");
    if (!tray) return;
    tray.innerHTML = "";
    if (!state.pendingImages.length) { tray.classList.add("hidden"); return; }
    tray.classList.remove("hidden");
    state.pendingImages.forEach((img, i) => {
      const div = document.createElement("div");
      div.className = "thumb";
      div.innerHTML = `<img src="${img.dataUrl}" alt="${esc(img.name || "image")}"><button class="rm" title="Remove"><i class="ph ph-x"></i></button>`;
      div.querySelector(".rm").addEventListener("click", () => {
        state.pendingImages.splice(i, 1);
        renderImageTray();
      });
      tray.appendChild(div);
    });
  }
  function fileToDataURL(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsDataURL(file);
    });
  }
  async function addImageFiles(files) {
    for (const f of files) {
      if (!f.type.startsWith("image/")) continue;
      try {
        const dataUrl = await fileToDataURL(f);
        state.pendingImages.push({ dataUrl, name: f.name });
      } catch (e) { console.warn("read failed", e); }
    }
    renderImageTray();
  }

  // ---------- send / stream ----------
  async function send() {
    if (state.streaming) return;
    const ta = $("#composer-input");
    let text = ta.value.trim();

    // "review this UI" → auto-capture the preview iframe and attach as an image
    // so the vision model actually sees it. Skip if the user already attached
    // something or the phrase is trivially present in an unrelated way.
    if (text && /\breview this ui\b/i.test(text) && !state.pendingImages.length && state.currentHtml) {
      const canvas = await captureIframePng();
      if (canvas) {
        const dataUrl = canvas.toDataURL("image/png");
        state.pendingImages.push({ dataUrl, name: `ui-${Date.now()}.png` });
        renderImageTray();
      }
    }

    const images = state.pendingImages.slice();
    if (!text && !images.length) return;
    if (!state.settings.model) {
      alert("Pick a model in Settings first.");
      openSettings();
      return;
    }
    ta.value = "";
    autoResize(ta);
    if (state.chatId) localStorage.removeItem("accuretta:draft:" + state.chatId);
    state.pendingImages = [];
    renderImageTray();

    // show the image count in the user bubble so they know what got sent
    const bubbleText = images.length
      ? (text ? `${text}\n\n📎 ${images.length} image${images.length > 1 ? "s" : ""} attached` : `📎 ${images.length} image${images.length > 1 ? "s" : ""} attached`)
      : text;
    const userMsg = { role: "user", content: bubbleText, t: Math.floor(Date.now() / 1000) };
    state.messages.push(userMsg);
    $("#chat-inner").appendChild(renderBubble(userMsg));
    scrollToBottom(true);
    renderCtxGauge();

    // placeholder agent bubble
    const agentRow = document.createElement("div");
    agentRow.className = "bubble-row";
    agentRow.innerHTML = `
      <div class="avatar"><i class="ph-bold ph-sparkle" style="font-size:12px"></i></div>
      <div class="bubble-col">
        <div class="think-line" data-label="Thinking"><i class="ph ph-brain"></i><span class="shimmer">Thinking…</span></div>
        <div class="tool-stack" id="tool-stack"></div>
        <div class="bubble agent hidden" id="stream-bubble"></div>
        <div class="bubble-meta streaming">${esc(state.settings.model)} · streaming<span class="typing"><span></span><span></span><span></span></span></div>
      </div>`;
    $("#chat-inner").appendChild(agentRow);
    scrollToBottom(true);

    state.streaming = true;
    state.abortCtl = new AbortController();
    setStreamingUI(true);

    try {
      await streamChat(text, agentRow, state.abortCtl.signal, images);
    } catch (e) {
      const b = agentRow.querySelector("#stream-bubble") || agentRow.querySelector(".bubble");
      if (b) {
        if (e.name === "AbortError") b.innerHTML += `<div style="color: var(--fg-faint); font-size:11px; margin-top:6px;">— stopped</div>`;
        else b.innerHTML = `<span style="color: var(--danger)">error: ${esc(e.message)}</span>`;
      }
    } finally {
      state.streaming = false;
      state.abortCtl = null;
      setStreamingUI(false);
      await loadChats();
      renderChatList();
    }
  }

  function setStreamingUI(on) {
    $("#btn-send").classList.toggle("hidden", on);
    $("#btn-stop").classList.toggle("hidden", !on);
    $("#composer-input").disabled = false; // always allow typing next message
  }

  function stopStreaming() {
    // tell the bridge to force-close the llama-server socket first — otherwise
    // generation keeps running server-side until it hits its own limit.
    const cid = state.chatId;
    if (cid) {
      try {
        fetch("/api/cancel", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: cid }),
          keepalive: true,
        }).catch(() => {});
      } catch {}
    }
    if (state.abortCtl) {
      try { state.abortCtl.abort(); } catch {}
    }
  }

  async function streamChat(text, agentRow, signal, images, opts) {
    const regenerate = !!(opts && opts.regenerate);
    const bubble = agentRow.querySelector("#stream-bubble");
    const toolStack = agentRow.querySelector("#tool-stack");
    let buf = "";
    const toolCards = new Map();

    // heartbeat: if no delta arrives, rotate through varied status lines
    // so the user sees the model is alive (not frozen). Mix of plain progress
    // and dry one-liners. Never repeats until the pool is exhausted.
    const idlePool = [
      "still working", "thinking it through", "crunching tokens",
      "wrangling the model", "hitting the monitor with a hammer",
      "politely asking the weights", "re-reading the prompt",
      "weighing options", "arguing with itself", "lining up the next move",
      "checking its own math", "rehearsing the reply", "taking the scenic route",
      "compiling thoughts", "sharpening the pencil", "consulting the rubber duck",
      "shaking the dice", "yelling at the GPU",
    ];
    let pool = idlePool.slice();
    let currentIdle = "still working";
    let lastActivity = Date.now();
    let lastRotate = 0;
    const started = lastActivity;
    const markActivity = () => { lastActivity = Date.now(); };
    const heartbeat = setInterval(() => {
      const line = agentRow.querySelector(".think-line");
      if (!line || line.classList.contains("done")) return;
      const span = line.querySelector("span");
      if (!span || !span.classList.contains("shimmer")) return;
      const idle = Math.floor((Date.now() - lastActivity) / 1000);
      const total = Math.floor((Date.now() - started) / 1000);
      if (idle < 3) return;
      // rotate phrase every 6 seconds of continuous idleness
      if (Date.now() - lastRotate > 6000) {
        if (!pool.length) pool = idlePool.slice();
        currentIdle = pool.splice(Math.floor(Math.random() * pool.length), 1)[0];
        lastRotate = Date.now();
      }
      span.textContent = `${currentIdle}… ${total}s`;
    }, 1000);

    const resp = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: state.chatId,
        message: text,
        mode: state.mode,
        images: (images || []).map(x => x.dataUrl),
        regenerate,
      }),
      signal,
    });
    if (!resp.body) throw new Error("no response body");

    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let carry = "";
    let ended = false;

    try {
      while (!ended) {
        const { value, done } = await reader.read();
        if (done) break;
        carry += dec.decode(value, { stream: true });
        const chunks = carry.split(/\n\n/);
        carry = chunks.pop();
        for (const chunk of chunks) {
          const line = chunk.split("\n").find(l => l.startsWith("data: "));
          if (!line) continue;
          let evt;
          try { evt = JSON.parse(line.slice(6)); } catch { continue; }
          handleEvent(evt, { bubble, toolStack, toolCards, row: agentRow, getBuf: () => buf, setBuf: v => buf = v });
          markActivity();
          if (evt.type === "chat_end") { ended = true; break; }
        }
      }
    } finally {
      try { await reader.cancel(); } catch {}
      clearInterval(heartbeat);
      if (agentRow) {
        updateThinkLine(agentRow, false);
        const meta = agentRow.querySelector(".bubble-meta");
        if (meta) {
          meta.classList.remove("streaming");
          meta.querySelectorAll(".typing").forEach(d => d.remove());
        }
      }
      // safety net: if the model ran tools or thought for a while but ended
      // without a visible answer, surface what we have so the user isn't
      // staring at nothing. Promote the tail of thinking if it's substantive.
      if (bubble && bubble.classList.contains("hidden")) {
        const { thinking } = splitThinking(buf);
        const hadTools = toolStack && toolStack.children.length > 0;
        bubble.classList.remove("hidden");
        bubble.classList.add("quiet");
        if (thinking && thinking.length > 40) {
          const tail = thinking.length > 900 ? "…" + thinking.slice(-900) : thinking;
          bubble.innerHTML = `<div style="margin-bottom:6px;opacity:0.7;font-size:11px;">(model spent its whole budget thinking — here's the tail)</div><pre style="white-space:pre-wrap;font-family:inherit;margin:0;">${esc(tail)}</pre>`;
        } else {
          bubble.textContent = hadTools
            ? "(model ended turn without a reply — ask it what it found, or try again)"
            : "(no response — try raising Max reply tokens in Settings)";
        }
      }
    }
  }

  // strip reasoning wrappers from several model families so the chat bubble
  // only shows the final answer. Accumulate thinking text into the think line.
  function splitThinking(buf) {
    // tags observed: <think>, <thinking>, <reasoning>, and <|thinking|>…<|/thinking|>.
    // many local models (Qwen/DeepSeek/Nemotron) emit bare </think> with no opening tag,
    // sometimes multiple times between tool rounds. rule: everything up to the LAST closing
    // reasoning tag is thinking; everything after is the visible answer.
    const closeRe = /<\/(?:think|thinking|reasoning)>|<\|\/thinking\|>/gi;
    let lastClose = -1;
    let m;
    while ((m = closeRe.exec(buf)) !== null) lastClose = m.index + m[0].length;

    let thinking = "";
    let content = "";
    if (lastClose >= 0) {
      thinking = buf.slice(0, lastClose);
      content = buf.slice(lastClose);
    } else {
      // no closing tag yet — if an opening tag is present, everything from it is in-flight thinking
      const openIdx = buf.search(/<(?:think|thinking|reasoning)>|<\|thinking\|>/i);
      if (openIdx >= 0) {
        content = buf.slice(0, openIdx);
        thinking = buf.slice(openIdx);
      } else {
        content = buf;
      }
    }
    const stripTags = /<\/?(?:think|thinking|reasoning)>|<\|\/?thinking\|>/gi;
    thinking = thinking.replace(stripTags, "").trim();
    content = content.replace(stripTags, "");
    // strip model-specific content delimiters that leak into output:
    //   GLM 4.x: ◁begin_of_box▷ … ◁end_of_box▷  and the <|…|> variants
    //   Command-R: <|START_OF_TURN_TOKEN|> etc.
    //   generic: <|im_start|>assistant / <|im_end|>, <|eot_id|>, [INST] wrappers
    const junk = [
      /◁\|?begin_of_box\|?▷/gi,
      /◁\|?end_of_box\|?▷/gi,
      /<\|?begin_of_box\|?>/gi,
      /<\|?end_of_box\|?>/gi,
      /<\|im_start\|>(?:assistant|user|system)?/gi,
      /<\|im_end\|>/gi,
      /<\|eot_id\|>/gi,
      /<\|start_header_id\|>[\s\S]*?<\|end_header_id\|>/gi,
      /<\|(?:START|END)_OF_TURN_TOKEN\|>/gi,
      /<\|begin_of_text\|>/gi,
      /<\|end_of_text\|>/gi,
      /\[\/?INST\]/gi,
      /<s>|<\/s>/gi,
    ];
    for (const re of junk) { thinking = thinking.replace(re, ""); content = content.replace(re, ""); }
    return { thinking: thinking.trim(), content };
  }
  function updateThinkLine(row, running, label) {
    const line = row.querySelector(".think-line");
    if (!line) return;
    const span = line.querySelector("span");
    const icon = line.querySelector("i");
    if (!running) {
      line.classList.add("done");
      span.classList.remove("shimmer");
      span.textContent = label || "Thought for a moment";
      icon.className = "ph ph-check";
      return;
    }
    if (label) span.textContent = label;
  }
  function handleEvent(evt, ctx) {
    const { bubble, toolStack, toolCards, row } = ctx;
    if (evt.type === "delta") {
      const newBuf = ctx.getBuf() + evt.content;
      ctx.setBuf(newBuf);
      // Throttled gauge update during streaming
      if (!state._lastGaugeUpdate || Date.now() - state._lastGaugeUpdate > 500) {
        renderCtxGauge();
        state._lastGaugeUpdate = Date.now();
      }
      const { thinking, content } = splitThinking(newBuf);
      if (thinking && ctx.row) {
        // first few words of current thinking snippet, shimmering
        const preview = thinking.split(/\s+/).slice(-12).join(" ");
        updateThinkLine(ctx.row, true, preview || "Thinking…");
      }
      if (content.trim()) {
        bubble.classList.remove("hidden");
        bubble.innerHTML = renderMarkdown(content);
        enhanceCodeBlocks(bubble);
        if (ctx.row) updateThinkLine(ctx.row, false);
      }
      scrollToBottom();
    } else if (evt.type === "tool_start") {
      const card = document.createElement("div");
      card.className = "tool-line running";
      const customIcon = toolIconHtml(evt.name, "run");
      const iconHtml = customIcon || `<i class="ph ph-circle-notch"></i>`;
      card.innerHTML = `${iconHtml}<span class="shimmer">${esc(toolLabel(evt.name, evt.arguments))}</span>`;
      card.dataset.name = evt.name || "";
      // Inline tools (commands + web_search) render directly in the chat so
      // their paths/commands/result-chips stay visible. Everything else folds
      // into a collapsible wrench group so reads/listings don't wall-of-text.
      if (isInlineTool(evt.name)) {
        toolStack.appendChild(card);
      } else {
        getOrCreateToolGroup(toolStack).body.appendChild(card);
        updateToolGroupHead(toolStack);
      }
      scrollToBottom();
    } else if (evt.type === "tool_stream") {
      const cards = Array.from(toolStack.querySelectorAll(".tool-line.running"));
      const card = cards.reverse().find(c => c.dataset.name === evt.name);
      if (card) {
        const span = card.querySelector("span");
        if (span) span.textContent = (evt.text || "").slice(-120);
      }
    } else if (evt.type === "heartbeat") {
      // while a long tool runs, the backend sends heartbeats — keep the shimmer alive
      const line = row && row.querySelector(".think-line");
      if (line && !line.classList.contains("done")) {
        const span = line.querySelector("span");
        if (span && span.classList.contains("shimmer")) {
          span.textContent = (evt.note || "working…").slice(0, 80);
        }
      }
    } else if (evt.type === "tool_result") {
      const cards = Array.from(toolStack.querySelectorAll(".tool-line.running"));
      const card = cards.reverse().find(c => c.dataset.name === evt.name);
      if (card) {
        const isErr = evt.result && evt.result.error;
        card.classList.remove("running");
        card.classList.add(isErr ? "err" : "done");
        const customIcon = toolIconHtml(evt.name, isErr ? "err" : "done");
        const iconHtml = customIcon || `<i class="ph ${isErr ? "ph-x-circle" : "ph-check"}"></i>`;
        const label = toolResultLabel(evt.name, evt.result);
        card.innerHTML = `${iconHtml}<span>${esc(label)}</span>`;
        // web_search: append link-chip row beneath the line so the user can click straight through.
        if (!isErr && evt.name === "web_search") {
          const chips = renderWebSearchChips(evt.result && evt.result.results);
          if (chips) {
            const wrap = document.createElement("div");
            wrap.className = "web-results-wrap";
            wrap.appendChild(card.cloneNode(true));
            wrap.insertAdjacentHTML("beforeend", chips);
            card.replaceWith(wrap);
          }
        }
        // network_snapshot: render bar-chart card so the user sees what was captured.
        if (!isErr && evt.name === "network_snapshot") {
          const chart = renderNetworkChart(evt.result);
          if (chart) {
            const wrap = document.createElement("div");
            wrap.className = "web-results-wrap";
            wrap.appendChild(card.cloneNode(true));
            wrap.insertAdjacentHTML("beforeend", chart);
            card.replaceWith(wrap);
          }
        }
        updateToolGroupHead(toolStack);
      }
    } else if (evt.type === "context_trimmed") {
      // Conveyor belt elision notice — show a single pill above the agent
      // row's tool stack. Replaces any prior pill from this turn so re-rounds
      // don't stack pills.
      if (row) {
        let pill = row.querySelector(".ctx-trim-pill");
        if (!pill) {
          pill = document.createElement("div");
          pill.className = "ctx-trim-pill";
          const tip = "Conversation exceeds context window. Older middle messages aren't sent to the model to save space. Your system prompt and first message are always preserved.";
          pill.innerHTML = `
            <i class="ph ph-arrows-in-line-horizontal"></i>
            <span class="ctx-trim-text"></span>
            <i class="ph ph-info ctx-trim-info" title="${esc(tip)}"></i>`;
          // Insert above tool-stack so it sits at the top of the agent column.
          const stack = row.querySelector(".tool-stack");
          if (stack && stack.parentNode) stack.parentNode.insertBefore(pill, stack);
          else row.appendChild(pill);
        }
        const text = pill.querySelector(".ctx-trim-text");
        if (text) text.textContent = `${evt.dropped} message${evt.dropped === 1 ? "" : "s"} summarized`;
      }
    } else if (evt.type === "version_saved") {
      state.versions.push(evt.version);
      renderVersions();
      setActiveVersion(evt.version.id);
    } else if (evt.type === "stats") {
      const tok = evt.eval_count;
      const dur = (evt.eval_duration || 0) / 1e9;
      const tps = dur > 0 ? (tok / dur).toFixed(1) : "—";
      const meta = bubble.parentElement.querySelector(".bubble-meta");
      if (meta) {
        meta.textContent = `${state.settings.model} · ${tok} tok · ${tps} tok/s`;
        if (state.streaming && meta.classList.contains("streaming")) {
          const dots = document.createElement("span");
          dots.className = "typing";
          dots.innerHTML = "<span></span><span></span><span></span>";
          meta.appendChild(dots);
        }
      }
      if (Number.isFinite(tok)) {
        state.tokTotal += tok;
        renderTokTotal();
      }
      // stash for the final message object
      state._lastMsgTokens = tok;
      state._lastMsgPromptTokens = evt.prompt_eval_count;
      // refresh gauge live — prompt_eval_count is the truth from llama-server,
      // and tool-heavy turns can blow past where the char-count estimate sits.
      renderCtxGauge();
    } else if (evt.type === "final") {
      const full = evt.message.content || "";
      const msg = {
        role: "assistant",
        content: full,
        t: Math.floor(Date.now() / 1000),
        tokens: state._lastMsgTokens || 0,
        prompt_tokens: state._lastMsgPromptTokens || 0,
      };
      state.messages.push(msg);
      state._lastMsgTokens = 0;
      state._lastMsgPromptTokens = 0;
      // update the meta tooltip on the bubble we just rendered
      const rows = [...document.querySelectorAll("#chat-inner .bubble-row")];
      const lastRow = rows.reverse().find(r => r.querySelector(".bubble.agent"));
      if (lastRow) {
        const meta = lastRow.querySelector(".bubble-meta");
        if (meta && msg.tokens) {
          meta.title = `${msg.tokens.toLocaleString()} tokens${msg.prompt_tokens ? ` (prompt: ${msg.prompt_tokens.toLocaleString()})` : ""}`;
        }
      }
      // parse companion files emitted alongside the primary html block
      // (```css path=style.css ..., ```js path=script.js ..., etc.)
      const files = parseMultiFileBlocks(full);
      if (Object.keys(files).length) {
        state.currentFiles = files;
        if (state.currentHtml) renderPreview();
      }
      renderCtxGauge();
      renderRegenerateChip();
    } else if (evt.type === "notice") {
      toast(evt.note || "", "info", 3000, "ctx-notice");
    } else if (evt.type === "error") {
      bubble.innerHTML = `<span style="color: var(--danger)">error: ${esc(evt.error)}</span>`;
    }
  }

  // ---------- versions / preview ----------
  async function loadVersions() {
    if (!state.chatId) return;
    try {
      const r = await api(`/api/versions/${state.chatId}`);
      state.versions = r.versions || [];
    } catch { state.versions = []; }
    renderVersions();
    if (state.versions.length) {
      setActiveVersion(state.versions[state.versions.length - 1].id);
    } else {
      clearPreview();
    }
  }

  function renderVersions() {
    const bar = $("#version-bar");
    bar.innerHTML = "";
    if (!state.versions.length) {
      bar.innerHTML = `<span id="versions-empty" style="color:var(--fg-faint)">no versions yet</span><span class="spacer"></span>`;
      return;
    }
    const maxVisible = state._versionsExpanded ? Infinity : 8;
    const hiddenCount = Math.max(0, state.versions.length - maxVisible);
    const visible = state._versionsExpanded ? state.versions : state.versions.slice(-maxVisible);
    if (hiddenCount > 0) {
      const expand = document.createElement("button");
      expand.className = "version-chip";
      expand.innerHTML = `<span class="n">…</span><span style="opacity:.6">+${hiddenCount} more</span>`;
      expand.title = `Show all ${state.versions.length} versions`;
      expand.addEventListener("click", () => {
        state._versionsExpanded = true;
        renderVersions();
      });
      bar.appendChild(expand);
    }
    for (const v of visible) {
      const wrap = document.createElement("span");
      wrap.className = "version-wrap" + (v.id === state.activeVersion ? " active" : "");
      const chip = document.createElement("button");
      chip.className = "version-chip" + (v.id === state.activeVersion ? " active" : "");
      chip.innerHTML = `<span class="n">v${String(v.n).padStart(2, "0")}</span>${v.label ? `<span style="opacity:.6">· ${esc(v.label).slice(0, 32)}</span>` : ""}`;
      chip.title = `${v.id} · ${humanBytes(v.bytes)} · ${relTime(v.t)}`;
      chip.addEventListener("click", () => setActiveVersion(v.id));
      wrap.appendChild(chip);
      const rerun = document.createElement("button");
      rerun.className = "version-rerun";
      rerun.type = "button";
      rerun.title = "Re-run: reload this version into the preview";
      rerun.innerHTML = `<i class="ph ph-arrow-counter-clockwise"></i>`;
      rerun.addEventListener("click", (e) => {
        e.stopPropagation();
        setActiveVersion(v.id);
        toast(`v${String(v.n).padStart(2, "0")} re-loaded`, "info", 1600, "vrerun");
      });
      wrap.appendChild(rerun);
      bar.appendChild(wrap);
    }
    const spacer = document.createElement("span");
    spacer.className = "spacer";
    bar.appendChild(spacer);
  }

  async function setActiveVersion(vid) {
    state.activeVersion = vid;
    const resp = await fetch(`/api/versions/${state.chatId}/${vid}`);
    const html = await resp.text();
    state.currentHtml = html;
    // companion-file map is per-turn; switching to a persisted version clears it
    state.currentFiles = {};
    const v = state.versions.find(x => x.id === vid);
    $("#preview-url").textContent = vid;
    $("#preview-meta").textContent = v ? `v${String(v.n).padStart(2, "0")} · ${relTime(v.t)}` : "—";
    $("#preview-size").textContent = humanBytes((html || "").length);
    renderPreview();
    renderVersions();
    // auto-open preview pane if collapsed
    if (app.classList.contains("preview-collapsed") && !isMobile()) {
      app.classList.remove("preview-collapsed");
    }
  }

  function clearPreview() {
    state.currentHtml = "";
    state.currentFiles = {};
    state.activeVersion = null;
    $("#preview-url").textContent = "—";
    $("#preview-meta").textContent = "—";
    $("#preview-size").textContent = "—";
    $("#preview-frame").classList.add("hidden");
    $("#code-view").classList.add("hidden");
    $("#preview-empty").classList.remove("hidden");
    renderVersions();
  }

  function injectCspIfNeeded(html) {
    if (state.settings.allow_web_preview !== false) return html;
    // when Tailwind CDN is on we must relax CSP enough to load it, otherwise the script is blocked.
    const scriptSrc = state.settings.use_tailwind_cdn
      ? "'unsafe-inline' 'self' data: https://cdn.tailwindcss.com"
      : "'unsafe-inline' 'self' data:";
    const styleSrc = state.settings.use_tailwind_cdn
      ? "'unsafe-inline' 'self' data: https://cdn.tailwindcss.com"
      : "'unsafe-inline' 'self' data:";
    const connectSrc = state.settings.use_tailwind_cdn
      ? "'self' https://cdn.tailwindcss.com"
      : "'self'";
    const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'self' data: blob:; style-src ${styleSrc}; script-src ${scriptSrc}; img-src 'self' data: blob: https:; font-src 'self' data: https:; connect-src ${connectSrc};">`;
    if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + csp);
    if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + "<head>" + csp + "</head>");
    return csp + html;
  }

  function injectTailwindIfNeeded(html) {
    if (!state.settings.use_tailwind_cdn) return html;
    // idempotent — bail out if the doc already pulls in Tailwind
    if (/cdn\.tailwindcss\.com/i.test(html)) return html;
    const tag = `<script src="https://cdn.tailwindcss.com"></script>`;
    if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + tag);
    if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + "<head>" + tag + "</head>");
    return tag + html;
  }

  // ---------- multi-file parsing ----------
  // the model may emit companion files via fenced blocks with an info string
  // like ```css path=style.css.  we collect them keyed by path so the preview
  // can inline them and Export Project can zip them unchanged.
  function parseMultiFileBlocks(text) {
    if (!text) return {};
    const out = {};
    // match fenced blocks with info strings containing path=<path>
    const re = /```([a-zA-Z0-9]+)?\s+([^\n`]*?path=([^\s`]+)[^\n`]*)\n([\s\S]*?)```/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const rawPath = (m[3] || "").trim().replace(/^["']|["']$/g, "");
      const body = m[4] || "";
      if (!rawPath) continue;
      // normalise + safety: strip leading slashes, no .. traversal, posix slashes only
      const safe = rawPath.replace(/\\/g, "/").replace(/^\/+/, "");
      if (safe.includes("..")) continue;
      out[safe] = body.replace(/\s+$/, "");
    }
    return out;
  }

  // Given the primary html and a map of extra files, return a single HTML
  // string suitable for the preview iframe with any linked local css/js
  // inlined.  Non-local hrefs are left alone.
  function inlineLocalAssets(html, files) {
    if (!html || !files || !Object.keys(files).length) return html;
    const keyOf = (href) => (href || "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
    // inline <link rel="stylesheet" href="..."> for local files
    html = html.replace(/<link\b([^>]*?)href=(["'])([^"']+)\2([^>]*)>/gi, (full, pre, _q, href, post) => {
      if (/rel\s*=\s*["']stylesheet/i.test(pre + post) || /rel\s*=\s*["']stylesheet/i.test(full)) {
        const key = keyOf(href);
        if (files[key] != null) return `<style data-inlined-from="${esc(key)}">\n${files[key]}\n</style>`;
      }
      return full;
    });
    // inline <script src="..."> for local files
    html = html.replace(/<script\b([^>]*?)src=(["'])([^"']+)\2([^>]*)><\/script>/gi, (full, pre, _q, src, post) => {
      const key = keyOf(src);
      if (files[key] != null) {
        const typeMatch = (pre + post).match(/type\s*=\s*(["'])([^"']+)\1/i);
        const typeAttr = typeMatch ? ` type="${esc(typeMatch[2])}"` : "";
        return `<script data-inlined-from="${esc(key)}"${typeAttr}>\n${files[key]}\n<\/script>`;
      }
      return full;
    });
    return html;
  }

  // ---------- console forwarder ----------
  // this script is injected into every preview so console.log / warn / error /
  // info and uncaught errors get posted back to the parent via postMessage.
  // the parent pushes them into the console-pane under the preview.
  const CONSOLE_FORWARDER = `<script>
(function(){
  if (window.__accConsoleWired) return;
  window.__accConsoleWired = true;
  var levels = ["log","info","warn","error","debug"];
  levels.forEach(function(lvl){
    var orig = console[lvl] && console[lvl].bind(console);
    console[lvl] = function(){
      try {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) {
          var a = arguments[i];
          if (a instanceof Error) parts.push(a.stack || a.message);
          else if (typeof a === "object") { try { parts.push(JSON.stringify(a)); } catch(_){ parts.push(String(a)); } }
          else parts.push(String(a));
        }
        parent.postMessage({ __acc: "console", level: lvl, text: parts.join(" ") }, "*");
      } catch(_){}
      if (orig) orig.apply(console, arguments);
    };
  });
  window.addEventListener("error", function(e){
    try { parent.postMessage({ __acc: "console", level: "error", text: (e.message||"error") + (e.filename?(" ("+e.filename+":"+e.lineno+")"):"") }, "*"); } catch(_){}
  });
  window.addEventListener("unhandledrejection", function(e){
    try { parent.postMessage({ __acc: "console", level: "error", text: "unhandled rejection: " + ((e.reason && (e.reason.stack||e.reason.message))||String(e.reason)) }, "*"); } catch(_){}
  });
})();
<\/script>`;

  function injectConsoleForwarder(html) {
    if (!html) return html;
    if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + CONSOLE_FORWARDER);
    if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + "<head>" + CONSOLE_FORWARDER + "</head>");
    return CONSOLE_FORWARDER + html;
  }

  function pushConsoleLog(level, text) {
    const entry = { level, text: String(text || ""), t: Date.now() };
    state.consoleLogs.push(entry);
    if (state.consoleLogs.length > 400) state.consoleLogs.splice(0, state.consoleLogs.length - 400);
    const body = document.getElementById("console-body");
    if (!body) return;
    const row = document.createElement("div");
    row.className = `c-row c-${level}`;
    row.textContent = entry.text;
    body.appendChild(row);
    body.scrollTop = body.scrollHeight;
  }

  function clearConsole() {
    state.consoleLogs = [];
    const body = document.getElementById("console-body");
    if (body) body.innerHTML = "";
  }

  // single global listener — receives postMessage from *any* preview iframe
  window.addEventListener("message", (e) => {
    const d = e && e.data;
    if (!d || d.__acc !== "console") return;
    pushConsoleLog(d.level || "log", d.text || "");
  });

  // ---------- viewport presets ----------
  const VIEWPORT_WIDTHS = { full: null, desktop: 1280, tablet: 820, mobile: 390 };

  function applyViewport(vp) {
    state.viewport = vp;
    const stage = $("#preview-stage");
    const frame = $("#preview-frame");
    if (!stage || !frame) return;
    const w = VIEWPORT_WIDTHS[vp];
    if (w) {
      stage.classList.add("vp-constrained");
      frame.style.maxWidth = w + "px";
      frame.style.marginInline = "auto";
    } else {
      stage.classList.remove("vp-constrained");
      frame.style.maxWidth = "";
      frame.style.marginInline = "";
    }
    $$(".vp-btn").forEach(b => b.classList.toggle("active", b.dataset.vp === vp));
  }

  function buildPreviewHtml() {
    let html = inlineLocalAssets(state.currentHtml, state.currentFiles);
    html = injectTailwindIfNeeded(html);
    html = injectConsoleForwarder(html);
    html = injectCspIfNeeded(html);
    return html;
  }

  function renderPreview() {
    if (!state.currentHtml) { clearPreview(); return; }
    $("#preview-empty").classList.add("hidden");
    if (state.view === "preview") {
      $("#code-view").classList.add("hidden");
      $("#preview-stage").classList.remove("hidden");
      // recreate iframe each time we switch back — srcdoc on a hidden iframe
      // can end up blank in some browsers. Cheap and always correct.
      const old = $("#preview-frame");
      const fresh = document.createElement("iframe");
      fresh.id = "preview-frame";
      fresh.className = "preview-frame";
      fresh.setAttribute("sandbox", "allow-scripts allow-forms allow-modals allow-popups");
      fresh.srcdoc = buildPreviewHtml();
      old.replaceWith(fresh);
    } else {
      $("#preview-stage").classList.add("hidden");
      const c = $("#code-view");
      c.classList.remove("hidden");
      c.innerHTML = highlightHTML(state.currentHtml);
    }
  }

  // ---------- preview: screenshot / export / review-UI ----------
  function safeSlug(s, fallback) {
    const t = (s || "").toString().toLowerCase()
      .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
    return t || fallback;
  }

  function currentProjectBase() {
    const v = state.versions.find(x => x.id === state.activeVersion);
    const title = (state.chats?.find?.(x => x.id === state.chatId)?.title) || "";
    return safeSlug(title || (v ? `version-${v.n}` : "preview"), "preview");
  }

  async function captureIframePng({ scale = 1 } = {}) {
    if (!state.currentHtml) {
      toast("Nothing in the preview yet.", "warn", 2200);
      return null;
    }
    if (typeof window.html2canvas !== "function") {
      toast("Screenshot library hasn't loaded yet — try again in a second.", "warn", 2500);
      return null;
    }
    // srcdoc iframes inherit the parent origin, so contentDocument is accessible
    const frame = $("#preview-frame");
    const doc = frame && frame.contentDocument;
    const body = doc && doc.body;
    if (!body) {
      toast("Preview frame isn't ready.", "warn", 2500);
      return null;
    }
    try {
      const canvas = await window.html2canvas(body, {
        backgroundColor: getComputedStyle(body).backgroundColor || "#ffffff",
        useCORS: true,
        allowTaint: true,
        scale,
        logging: false,
        windowWidth: doc.documentElement.scrollWidth,
        windowHeight: doc.documentElement.scrollHeight,
      });
      return canvas;
    } catch (e) {
      toast(`Screenshot failed: ${e.message || e}`, "err", 3500);
      return null;
    }
  }

  async function screenshotPreview() {
    const canvas = await captureIframePng();
    if (!canvas) return;
    canvas.toBlob((blob) => {
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${currentProjectBase()}-${Date.now()}.png`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("Screenshot saved", "ok", 2000, "ss");
    }, "image/png");
  }

  async function reviewUiAttach() {
    const canvas = await captureIframePng();
    if (!canvas) return;
    const dataUrl = canvas.toDataURL("image/png");
    state.pendingImages.push({ dataUrl, name: `ui-${Date.now()}.png` });
    renderImageTray();
    const ta = $("#composer-input");
    if (ta) {
      const existing = ta.value.trim();
      if (!/review this ui/i.test(existing)) {
        ta.value = existing ? `${existing}\n\nReview this UI — note what feels off and suggest concrete fixes.`
                            : "Review this UI — note what feels off and suggest concrete fixes.";
      }
      autoResize(ta);
      ta.focus();
    }
    toast("Preview attached — press Send to have the model review it.", "ok", 3000, "review");
  }

  async function saveSnapshot() {
    if (!state.currentHtml) {
      toast("Nothing in the preview yet.", "warn", 2200);
      return;
    }
    const base = currentProjectBase();
    const html = buildPreviewHtml();  // persist what the user actually sees
    const resp = await fetch("/api/snapshots", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: base, html }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || data.error) {
      toast(`Snapshot failed: ${data.error || resp.status}`, "err", 3500);
      return;
    }
    toast(`Saved: ${data.name}`, "ok", 2600, "snap");
  }

  async function copyPreviewAsDataUrl() {
    if (!state.currentHtml) {
      toast("Nothing in the preview yet.", "warn", 2200);
      return;
    }
    const html = buildPreviewHtml();
    const b64 = btoa(unescape(encodeURIComponent(html)));
    const url = `data:text/html;charset=utf-8;base64,${b64}`;
    try {
      await navigator.clipboard.writeText(url);
      toast(`Copied data URL (${Math.round(url.length / 1024)}KB)`, "ok", 2400, "dataurl");
    } catch {
      // clipboard may be blocked — fall back to a throwaway prompt
      try { window.prompt("Copy this data URL:", url); } catch {}
    }
  }

  function toggleConsolePane(force) {
    const want = typeof force === "boolean" ? force : !state.consoleOpen;
    state.consoleOpen = want;
    const pane = $("#console-pane");
    if (!pane) return;
    pane.classList.toggle("hidden", !want);
    $("#btn-toggle-console")?.classList.toggle("active", want);
  }

  async function exportProjectZip() {
    if (!state.currentHtml) {
      toast("Nothing in the preview yet.", "warn", 2200);
      return;
    }
    const base = currentProjectBase();
    const files = state.currentFiles || {};
    const hasCompanions = Object.keys(files).length > 0;

    // single-file path: just download the html
    if (!hasCompanions) {
      const blob = new Blob([state.currentHtml], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${base}.html`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("Downloaded HTML", "ok", 2000, "exp");
      return;
    }

    if (typeof window.JSZip !== "function") {
      toast("Zip library hasn't loaded yet — try again in a second.", "warn", 2500);
      return;
    }

    const zip = new window.JSZip();
    // if the model also emitted its own index.html path, prefer that verbatim;
    // otherwise write state.currentHtml as index.html
    if (!files["index.html"]) zip.file("index.html", state.currentHtml);
    for (const [path, body] of Object.entries(files)) zip.file(path, body);
    const blob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${base}.zip`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${Object.keys(files).length + (files["index.html"] ? 0 : 1)} files`, "ok", 2400, "exp");
  }

  // ---------- workspace ----------
  // ---- workspace file tree ----
  const FILE_ICON = {
    // scripts
    js: "ph-file-js", jsx: "ph-file-js", ts: "ph-file-ts", tsx: "ph-file-ts",
    py: "ph-file-py", rb: "ph-file-code", go: "ph-file-code", rs: "ph-file-rs",
    java: "ph-file-code", c: "ph-file-c", cpp: "ph-file-cpp", h: "ph-file-c",
    cs: "ph-file-cs", php: "ph-file-code", sh: "ph-terminal-window",
    ps1: "ph-terminal-window", bat: "ph-terminal-window", lua: "ph-file-code",
    // web
    html: "ph-file-html", htm: "ph-file-html", css: "ph-file-css",
    scss: "ph-file-css", sass: "ph-file-css", less: "ph-file-css",
    vue: "ph-file-vue", svelte: "ph-file-code",
    // data
    json: "ph-brackets-curly", yaml: "ph-brackets-angle", yml: "ph-brackets-angle",
    xml: "ph-brackets-angle", toml: "ph-brackets-angle", ini: "ph-brackets-angle",
    csv: "ph-table", tsv: "ph-table", sql: "ph-database", db: "ph-database",
    sqlite: "ph-database",
    // docs
    md: "ph-file-md", mdx: "ph-file-md", txt: "ph-file-text", rtf: "ph-file-text",
    pdf: "ph-file-pdf", doc: "ph-file-doc", docx: "ph-file-doc",
    xls: "ph-file-xls", xlsx: "ph-file-xls", ppt: "ph-file-ppt", pptx: "ph-file-ppt",
    // media
    png: "ph-file-image", jpg: "ph-file-image", jpeg: "ph-file-image",
    gif: "ph-file-image", webp: "ph-file-image", svg: "ph-file-svg",
    ico: "ph-file-image", bmp: "ph-file-image", avif: "ph-file-image",
    mp3: "ph-file-audio", wav: "ph-file-audio", flac: "ph-file-audio",
    ogg: "ph-file-audio", m4a: "ph-file-audio",
    mp4: "ph-file-video", mov: "ph-file-video", mkv: "ph-file-video",
    webm: "ph-file-video", avi: "ph-file-video",
    // archives
    zip: "ph-file-zip", rar: "ph-file-zip", "7z": "ph-file-zip",
    tar: "ph-file-zip", gz: "ph-file-zip", bz2: "ph-file-zip",
    // config
    env: "ph-key", lock: "ph-lock-simple", log: "ph-article",
    gitignore: "ph-git-branch", dockerfile: "ph-cube",
  };
  function fileIconFor(name, ext) {
    const lower = (name || "").toLowerCase();
    if (lower === "dockerfile") return "ph-cube";
    if (lower === "makefile") return "ph-hammer";
    if (lower === "license" || lower === "license.md") return "ph-scales";
    if (lower === "readme" || lower === "readme.md") return "ph-book-open-text";
    if (lower.startsWith(".git")) return "ph-git-branch";
    return FILE_ICON[ext] || "ph-file";
  }
  function folderLeafName(path) {
    return path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || path;
  }
  async function fetchFolderListing(path) {
    try {
      const r = await api(`/api/list-folder?path=${encodeURIComponent(path)}`);
      if (r.error) throw new Error(r.error);
      return r.entries || [];
    } catch (e) {
      return { _error: e.message || String(e) };
    }
  }
  function renderTreeNode(entry, depth) {
    const node = document.createElement("div");
    node.className = entry.is_dir ? "tree-node tree-dir" : "tree-node tree-file";
    node.style.setProperty("--depth", depth);
    const icon = entry.is_dir ? "ph-folder" : fileIconFor(entry.name, entry.ext);
    const chev = entry.is_dir ? `<i class="ph ph-caret-right tree-chev"></i>` : `<span class="tree-chev-spacer"></span>`;
    node.innerHTML = `
      <div class="tree-row" title="${esc(entry.path)}">
        ${chev}
        <i class="ph ${icon} tree-icon"></i>
        <span class="tree-name">${esc(entry.name)}</span>
      </div>
      ${entry.is_dir ? `<div class="tree-children" hidden></div>` : ""}`;
    if (entry.is_dir) {
      const rowEl = node.querySelector(".tree-row");
      const kids = node.querySelector(".tree-children");
      let loaded = false;
      rowEl.addEventListener("click", async (e) => {
        e.stopPropagation();
        const expanded = !kids.hasAttribute("hidden");
        if (expanded) {
          kids.setAttribute("hidden", "");
          node.classList.remove("open");
          return;
        }
        node.classList.add("open");
        kids.removeAttribute("hidden");
        if (!loaded) {
          kids.innerHTML = `<div class="tree-loading" style="--depth:${depth + 1}">loading…</div>`;
          const entries = await fetchFolderListing(entry.path);
          kids.innerHTML = "";
          if (entries._error) {
            kids.innerHTML = `<div class="tree-empty" style="--depth:${depth + 1}">${esc(entries._error)}</div>`;
          } else if (!entries.length) {
            kids.innerHTML = `<div class="tree-empty" style="--depth:${depth + 1}">empty</div>`;
          } else {
            for (const child of entries) kids.appendChild(renderTreeNode(child, depth + 1));
          }
          loaded = true;
        }
      });
    }
    return node;
  }

  function renderWorkspace() {
    const wrap = $("#ws-list");
    wrap.innerHTML = "";
    if (!state.workspace.folders.length) {
      wrap.innerHTML = `<div style="padding: 10px 12px; font-size: 11px; color: var(--fg-faint);">no folders. add one to let the agent read/write files.</div>`;
      return;
    }
    for (const f of state.workspace.folders) {
      const wrapper = document.createElement("div");
      wrapper.className = "ws-root";

      const header = document.createElement("div");
      header.className = "ws-folder";
      header.innerHTML = `
        <i class="ph ph-caret-right ws-chev"></i>
        <i class="ph ph-folder"></i>
        <span class="path" title="${esc(f)}">${esc(folderLeafName(f))}</span>
        <button class="rm" title="Remove"><i class="ph ph-x"></i></button>`;
      wrapper.appendChild(header);

      const tree = document.createElement("div");
      tree.className = "ws-tree";
      tree.hidden = true;
      wrapper.appendChild(tree);

      let loaded = false;
      header.querySelector(".rm").addEventListener("click", async (e) => {
        e.stopPropagation();
        const next = state.workspace.folders.filter(x => x !== f);
        await api("/api/workspace", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ folders: next }),
        });
        state.workspace.folders = next;
        renderWorkspace();
      });
      header.addEventListener("click", async () => {
        const wasOpen = wrapper.classList.toggle("open");
        tree.hidden = !wasOpen;
        if (wasOpen && !loaded) {
          tree.innerHTML = `<div class="tree-loading" style="--depth:1">loading…</div>`;
          const entries = await fetchFolderListing(f);
          tree.innerHTML = "";
          if (entries._error) {
            tree.innerHTML = `<div class="tree-empty" style="--depth:1">${esc(entries._error)}</div>`;
          } else if (!entries.length) {
            tree.innerHTML = `<div class="tree-empty" style="--depth:1">empty</div>`;
          } else {
            for (const child of entries) tree.appendChild(renderTreeNode(child, 1));
          }
          loaded = true;
        }
      });

      wrap.appendChild(wrapper);
    }
  }

  async function addWorkspaceFolder() {
    const inp = $("#ws-input");
    const v = inp.value.trim();
    if (!v) return;
    const next = Array.from(new Set([...state.workspace.folders, v]));
    const r = await api("/api/workspace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ folders: next }),
    });
    state.workspace = r;
    inp.value = "";
    $("#ws-add").classList.add("hidden");
    renderWorkspace();
  }

  // ---------- approvals ----------
  // compose a pre-flight summary of what a tool call will actually do.
  // purely cosmetic — the approval itself still lives on `a.command`.
  function approvalPreview(a) {
    const d = a.details || {};
    const kind = d.kind || "";
    const rows = [];
    const pair = (k, v) => rows.push(`<div class="pv-row"><span class="pv-k">${esc(k)}</span><span class="pv-v">${esc(v)}</span></div>`);
    if (kind === "write_file") {
      pair("path", d.path || "?");
      pair("size", (d.bytes || 0).toLocaleString() + " bytes");
      pair("overwrites", "yes, if exists");
    } else if (kind === "edit_file") {
      pair("path", d.path || "?");
      pair("edits", String(d.edits || "?"));
      if (d.preview) pair("preview", d.preview.slice(0, 120).replace(/\n/g, " "));
    } else if (kind === "delete") {
      pair("path", d.path || "?");
      pair("target", d.dir ? "directory" : "file");
      pair("reversible", "NO — permanent");
    } else if (kind === "desktop.launch") {
      pair("launches", d.target || "?");
      pair("allowlist check", "passed");
    } else if (kind === "desktop.focus") {
      pair("focus window", d.title || "?");
    } else if (kind === "desktop.click") {
      pair("click at", `${d.x ?? "?"}, ${d.y ?? "?"}`);
      pair("button", d.button || "left");
      if (d.clicks) pair("count", String(d.clicks));
    } else if (kind === "desktop.type") {
      pair("types", `${d.length ?? (d.text || "").length} chars`);
      if (d.text) pair("preview", d.text.slice(0, 80) + ((d.text || "").length > 80 ? "…" : ""));
    } else if (kind === "desktop.keys") {
      pair("presses", d.combo || "?");
    } else if (kind === "desktop.close") {
      pair("closes window", d.title || "?");
    } else if (kind === "launch") {
      pair("launches", d.path || "?");
    } else if (kind === "powershell") {
      pair("runs PowerShell", "check the command below");
    } else if (kind === "network_snapshot") {
      pair("reads", "active TCP/UDP connections + DNS cache");
      pair("admin needed", "no");
      pair("network access", "read-only — no packets sent");
    }
    return rows.length ? `<div class="pv">${rows.join("")}</div>` : "";
  }

  function renderApprovals() {
    const stack = $("#approval-stack");
    if (stack) stack.innerHTML = "";
    const chatInner = $("#chat-inner");
    if (!chatInner) return;
    chatInner.querySelectorAll(".approval-row").forEach(n => n.remove());

    for (const a of state.approvals.values()) {
      const row = document.createElement("div");
      row.className = "bubble-row approval-row";
      row.dataset.approvalId = a.id;
      const details = a.details || {};
      const tag = details.kind || "command";
      const isDesktop = String(tag).startsWith("desktop.") || tag === "ui.action";
      const isDestructive = ["delete", "write_file"].includes(tag);
      const card = document.createElement("div");
      card.className = "approval inline";
      if (isDesktop) card.classList.add("kind-desktop");
      if (isDestructive) card.classList.add("kind-destructive");
      card.innerHTML = `
        <div class="head">
          <i class="ph-bold ph-shield-warning"></i>
          <span class="t">${esc(a.title)}</span>
          <span class="tag">${esc(tag)}</span>
        </div>
        ${approvalPreview(a)}
        <details class="cmd-details">
          <summary>Command</summary>
          <div class="cmd">${esc(a.command)}</div>
        </details>
        <div class="actions">
          <button class="btn danger" data-act="deny"><i class="ph ph-x"></i>Deny</button>
          <button class="btn accent" data-act="approve"><i class="ph-bold ph-check"></i>Approve</button>
        </div>`;
      card.querySelector('[data-act="approve"]').addEventListener("click", () => decideApproval(a.id, "approve"));
      card.querySelector('[data-act="deny"]').addEventListener("click", () => decideApproval(a.id, "deny"));
      row.innerHTML = `
        <div class="avatar approval-avatar"><i class="ph-bold ph-shield-warning"></i></div>
        <div class="bubble-col"></div>`;
      row.querySelector(".bubble-col").appendChild(card);
      chatInner.appendChild(row);
    }
    if (state.approvals.size > 0) {
      requestAnimationFrame(() => scrollToBottom(true));
    }
  }

  async function decideApproval(id, decision) {
    state.approvals.delete(id);
    renderApprovals();
    await fetch("/api/approvals/decide", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, decision }),
    });
  }

  async function loadApprovals() {
    const r = await api("/api/approvals");
    state.approvals.clear();
    for (const a of r.pending || []) state.approvals.set(a.id, a);
    renderApprovals();
  }

  // ---------- SSE ----------
  function subscribeSSE() {
    const es = new EventSource("/api/events");
    es.onmessage = (e) => {
      let evt;
      try { evt = JSON.parse(e.data); } catch { return; }
      if (evt.type === "approval:new") {
        state.approvals.set(evt.approval.id, evt.approval);
        renderApprovals();
      } else if (evt.type === "approval:decided") {
        state.approvals.delete(evt.id);
        renderApprovals();
      } else if (evt.type === "settings:update") {
        loadSettings().then(renderStatus).then(renderModelPill);
      } else if (evt.type === "workspace:update") {
        loadWorkspace().then(renderWorkspace);
      } else if (evt.type === "chat:rename") {
        const c = state.chats && state.chats.chats && state.chats.chats[evt.chat_id];
        if (c) {
          c.title = evt.title;
          renderChatList();
        }
      } else if (evt.type === "desktop:panic") {
        if (evt.on) toast("desktop automation PANICKED — all actions blocked", "warn", 6000, "desktop-panic");
        else toast("desktop automation resumed", "ok", 2000, "desktop-panic");
        refreshDesktopStatus();
      } else if (evt.type === "memories:update") {
        if ($("#settings-drawer")?.classList.contains("open")) loadMemories();
      } else if (evt.type === "models:update") {
        loadModels().then(() => {
          if ($("#settings-drawer")?.classList.contains("open")) populateSettingsForm();
          renderModelPill();
        });
      }
    };
    es.onerror = () => {
      es.close();
      setTimeout(subscribeSSE, 3000);
    };
  }

  // ---------- settings drawer ----------
  async function openSettings() {
    $("#drawer-scrim").classList.add("open");
    $("#settings-drawer").classList.add("open");
    await loadModels();
    populateSettingsForm();
    loadSystemContext();
  }

  async function loadSystemContext() {
    const ta = $("#set-sysctx");
    const path = $("#sysctx-path");
    if (!ta) return;
    ta.value = "loading…";
    try {
      const r = await api("/api/system-context");
      ta.value = r.md || "";
      if (path) path.textContent = r.path || "";
    } catch (e) {
      ta.value = `(failed: ${e.message || e})`;
    }
  }
  async function saveSystemContext() {
    const ta = $("#set-sysctx");
    if (!ta) return;
    const btn = $("#btn-sysctx-save");
    if (btn) btn.disabled = true;
    try {
      await api("/api/system-context", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ md: ta.value }) });
    } catch (e) {
      alert(`save failed: ${e.message || e}`);
    } finally {
      if (btn) btn.disabled = false;
    }
  }
  // ---------- memories panel ----------
  function renderMemoriesList(items) {
    const host = $("#mem-list");
    if (!host) return;
    host.innerHTML = "";
    if (!items || !items.length) {
      host.innerHTML = `<div class="mem-empty">no memories yet — add one below, or let the model call <code>remember</code>.</div>`;
      return;
    }
    for (const m of items) {
      const row = document.createElement("div");
      row.className = "mem-item";
      const tags = Array.isArray(m.tags) && m.tags.length
        ? `<span class="mem-tags">${m.tags.map(t => `<span class="mem-tag">${esc(t)}</span>`).join("")}</span>`
        : "";
      row.innerHTML = `
        <div class="mem-text">${esc(m.text || "")}</div>
        <div class="mem-foot">
          ${tags}
          <span class="mem-ts">${m.t ? relTime(m.t) : ""}</span>
          <button class="btn ghost sm mem-del" type="button" title="Forget"><i class="ph ph-trash"></i></button>
        </div>`;
      row.querySelector(".mem-del").addEventListener("click", async () => {
        try {
          await api("/api/memories/forget", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: m.id }),
          });
        } catch (e) { toast("forget failed: " + e.message, "error"); }
      });
      host.appendChild(row);
    }
  }
  async function loadMemories() {
    try {
      const r = await api("/api/memories");
      renderMemoriesList(r.memories || []);
    } catch (e) {
      const host = $("#mem-list");
      if (host) host.innerHTML = `<div class="mem-empty">(failed: ${esc(e.message || String(e))})</div>`;
    }
  }
  async function addMemoryFromInput() {
    const input = $("#mem-add-text");
    if (!input) return;
    const text = (input.value || "").trim();
    if (!text) return;
    const btn = $("#btn-mem-add");
    if (btn) btn.disabled = true;
    try {
      await api("/api/memories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      input.value = "";
    } catch (e) {
      toast("add failed: " + e.message, "error");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function rescanSystemContext() {
    const btn = $("#btn-sysctx-rescan");
    const ta = $("#set-sysctx");
    if (btn) btn.disabled = true;
    if (ta) ta.value = "scanning…";
    try {
      const r = await api("/api/system-context/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      if (ta) ta.value = r.md || "";
    } catch (e) {
      if (ta) ta.value = `(rescan failed: ${e.message || e})`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }
  function closeSettings() {
    $("#drawer-scrim").classList.remove("open");
    $("#settings-drawer").classList.remove("open");
  }
  function populateSettingsForm() {
    const s = state.settings;
    const fill = (id, v) => { const el = $(id); if (el) el.value = v ?? ""; };

    // models folder + dropdown
    const dirInput = $("#set-models-dir");
    if (dirInput) dirInput.value = state.modelsDir || s.models_dir || "";
    const modelSel = $("#set-model");
    if (modelSel) {
      modelSel.innerHTML = "";
      const list = state.modelsList || [];
      const loaded = state.loadedModel || s.model_path || "";
      if (!list.length) {
        const msg = state.modelsError || "pick a models folder above";
        modelSel.innerHTML = `<option value="">(${msg})</option>`;
      } else {
        for (const m of list) {
          const o = document.createElement("option");
          o.value = m.path; o.textContent = m.name + (m.size_gb ? `  (${m.size_gb} GB)` : "");
          if (m.path === loaded || m.loaded) o.selected = true;
          modelSel.appendChild(o);
        }
      }
    }
    const hint = $("#set-model-hint");
    if (hint) {
      if (state.llamaRunning && state.loadedModel) {
        const name = state.loadedModel.split(/[\\/]/).pop();
        hint.textContent = `loaded: ${name}`;
      } else if (state.modelsDir) {
        hint.textContent = `${(state.modelsList || []).length} model(s) in ${state.modelsDir}`;
      } else {
        hint.textContent = "selecting a model loads it into llama-server.";
      }
    }
    const visionSel = $("#set-vision");
    if (visionSel) {
      visionSel.innerHTML = "";
      const emptyOpt = document.createElement("option");
      emptyOpt.value = ""; emptyOpt.textContent = "(none)";
      visionSel.appendChild(emptyOpt);
      for (const m of (state.modelsList || [])) {
        const o = document.createElement("option");
        o.value = m.path; o.textContent = m.name;
        if (m.path === s.vision_model) o.selected = true;
        visionSel.appendChild(o);
      }
    }

    fill("#set-ctx", s.num_ctx);
    fill("#set-gpu", s.num_gpu);
    fill("#set-batch", s.num_batch);
    fill("#set-thread", s.num_thread);
    fill("#set-predict", s.num_predict);
    const kvSel = $("#set-kv");
    if (kvSel) kvSel.value = s.kv_cache_type || "q8_0";
    fill("#set-temp", s.temperature);
    fill("#set-topp", s.top_p);
    fill("#set-topk", s.top_k ?? 40);
    fill("#set-minp", s.min_p ?? 0.05);
    fill("#set-repeat", s.repeat_penalty ?? 1.1);
    fill("#set-presence", s.presence_penalty ?? 0);
    fill("#set-frequency", s.frequency_penalty ?? 0);
    $("#sw-thinking")?.classList.toggle("on", s.enable_thinking !== false);
    fill("#set-think-budget", s.thinking_budget ?? 2048);
    $("#sw-dark").classList.toggle("on", s.theme === "dark");
    $("#sw-web").classList.toggle("on", s.allow_web_preview !== false);

    // IDE toggles mirror back into the composer chips
    reflectIdeToggles();

    // desktop automation
    $("#sw-desktop-enabled")?.classList.toggle("on", !!s.desktop_enabled);
    const al = $("#set-desktop-allowlist");
    if (al) al.value = (s.desktop_app_allowlist || []).join("\n");
    fill("#set-desktop-rate", s.desktop_max_actions_per_minute || 30);
    refreshDesktopStatus();
    // memories panel
    loadMemories();
  }

  async function refreshDesktopStatus() {
    try {
      const r = await api("/api/desktop/status");
      const badge = $("#desktop-deps-badge");
      if (badge) {
        const missing = [];
        if (!r.have_pyautogui) missing.push("pyautogui");
        if (!r.have_pil) missing.push("Pillow");
        if (!r.have_pygetwindow) missing.push("pygetwindow");
        badge.textContent = missing.length
          ? `missing: pip install ${missing.join(" ")}`
          : "all libs installed";
        badge.style.color = missing.length ? "var(--danger)" : "var(--mint-3)";
      }
      const ps = $("#desktop-panic-state");
      if (ps) {
        ps.textContent = r.panic ? "PANIC — all actions blocked" : "ready";
        ps.style.color = r.panic ? "var(--danger)" : "var(--fg-faint)";
      }
    } catch {}
  }
  // settings whose changes require relaunching llama-server (load-time flags)
  const LOAD_TIME_KEYS = ["num_ctx", "num_gpu", "num_batch", "num_thread", "kv_cache_type", "model_path"];

  async function collectAndSaveSettings() {
    const n = (id) => Number($(id).value);
    const modelPath = $("#set-model").value || "";
    const payload = {
      model_path: modelPath,
      model: modelPath ? modelPath.split(/[\\/]/).pop().replace(/\.gguf$/i, "") : "",
      models_dir: ($("#set-models-dir")?.value || "").trim(),
      vision_model: $("#set-vision").value,
      num_ctx: n("#set-ctx") || 8192,
      num_gpu: n("#set-gpu"),
      num_batch: n("#set-batch") || 512,
      num_thread: n("#set-thread"),
      num_predict: n("#set-predict"),
      kv_cache_type: $("#set-kv")?.value || "q8_0",
      temperature: n("#set-temp"),
      top_p: n("#set-topp"),
      top_k: n("#set-topk"),
      min_p: n("#set-minp"),
      repeat_penalty: n("#set-repeat"),
      presence_penalty: n("#set-presence"),
      frequency_penalty: n("#set-frequency"),
      enable_thinking: $("#sw-thinking")?.classList.contains("on") !== false,
      thinking_budget: n("#set-think-budget"),
      theme: $("#sw-dark").classList.contains("on") ? "dark" : "light",
      allow_web_preview: $("#sw-web").classList.contains("on"),
      desktop_enabled: $("#sw-desktop-enabled")?.classList.contains("on") || false,
      desktop_app_allowlist: ($("#set-desktop-allowlist")?.value || "")
        .split("\n").map(x => x.trim()).filter(Boolean),
      desktop_max_actions_per_minute: Math.max(1, Math.min(300, n("#set-desktop-rate") || 30)),
      use_tailwind_cdn: !!state.settings.use_tailwind_cdn,
      ide_multifile: !!state.settings.ide_multifile,
    };

    // Detect which load-time keys actually changed → triggers a llama-server
    // restart so the new flags take effect without the user having to know.
    const prev = state.settings || {};
    const changedLoadKeys = LOAD_TIME_KEYS.filter(k => String(prev[k] ?? "") !== String(payload[k] ?? ""));

    await saveSettings(payload);
    applyTheme(payload.theme === "dark");

    if (changedLoadKeys.length && payload.model_path) {
      const tid = "reload-llama";
      toast(`reloading model (${changedLoadKeys.join(", ")})…`, "info", 60000, tid);
      try {
        await api("/api/models/load", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ path: payload.model_path }),
        });
        toast("model reloaded with new settings", "ok", 2500, tid);
      } catch (e) {
        toast("reload failed: " + (e.message || e), "error", 6000, tid);
      }
    }
    closeSettings();
  }

  async function prewarmModel(model) {
    if (!model) return;
    toast(`loading ${model.split("/").pop()}…`, "info", 30000, "prewarm");
    try {
      await api("/api/prewarm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model }) });
      toast(`${model.split("/").pop()} ready`, "ok", 2500, "prewarm");
    } catch {
      toast("prewarm failed — will load on first send", "warn", 3000, "prewarm");
    }
  }

  function applyTheme(dark) {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    $("#btn-theme").innerHTML = dark ? '<i class="ph ph-sun"></i>' : '<i class="ph ph-moon"></i>';
  }

  function renderStatus() {
    // status pill was removed; keep function as a no-op shim so callers still work,
    // and update the context gauge since token counts may have changed.
    renderCtxGauge();
  }
  function renderCtxGauge() {
    const arc = $("#ctx-gauge-arc");
    const label = $("#ctx-gauge-label");
    if (!arc || !label) return;
    const capacity = Math.max(1, Number(state.settings.num_ctx) || 32768);
    // Prefer llama-server's actual reported prompt-token count from the most
    // recent turn. The visible-bubble char count below is blind to tool calls,
    // tool results, and intermediate assistant rounds — for tool-heavy work
    // (firmware, multi-step research) it under-reports by 10x or more.
    const livePromptTokens = Number(state._lastMsgPromptTokens || 0);
    let used, source;
    if (livePromptTokens > 0) {
      used = Math.min(capacity, livePromptTokens);
      source = "llama-server prompt_eval_count";
    } else {
      const systemPromptChars = 2500;
      const msgChars = (state.messages || []).reduce((a, m) => {
        const content = String(m.content || "");
        const multiplier = m.role === "tool" ? 1.5 : 1.0;
        return a + (content.length * multiplier);
      }, 0);
      const imageOverhead = (state.pendingImages || []).length * 500;
      const totalChars = systemPromptChars + msgChars + imageOverhead;
      used = Math.min(capacity, Math.round(totalChars / 3.0));
      source = "char-count estimate (no live data yet)";
    }
    const pct = Math.min(1, used / capacity);
    const circ = 2 * Math.PI * 13;
    arc.setAttribute("stroke-dasharray", circ.toFixed(2));
    arc.setAttribute("stroke-dashoffset", (circ * (1 - pct)).toFixed(2));
    label.textContent = `${Math.round(pct * 100)}%`;
    const gauge = $("#ctx-gauge");
    gauge.classList.toggle("warn", pct >= 0.7 && pct < 0.9);
    gauge.classList.toggle("crit", pct >= 0.9);
    gauge.title = `${used.toLocaleString()} / ${capacity.toLocaleString()} tokens (~${Math.round(pct * 100)}%)\nsource: ${source}`;
  }
  function renderTokTotal() {
    const el = $("#tok-total");
    if (!el) return;
    el.textContent = `${state.tokTotal.toLocaleString()} tok`;
  }
  function renderModelPill() {
    const pill = $("#model-pill");
    const loadedPath = state.loadedModel || state.settings.model_path || state.settings.model || "";
    if (loadedPath) {
      const name = String(loadedPath).split(/[\\/]/).pop();
      pill.textContent = name;
      pill.title = "Click to change model";
    } else if (state.models && state.models.length) {
      pill.textContent = "select model";
      pill.title = "Click to pick a model";
    } else {
      pill.textContent = "no models";
      pill.title = state.modelsError || "Pick a models folder in Settings";
    }
  }

  // ---------- mobile tabs ----------
  function applyMobileTab() {
    $$(".mobile-tab").forEach(t => t.classList.toggle("active", t.dataset.mtab === state.mobileTab));
    app.classList.remove("m-tab-chat", "m-tab-sessions", "m-tab-approvals", "m-tab-settings");
    if (state.mobileTab === "settings") {
      openSettings();
      state.mobileTab = "chat";
      $$(".mobile-tab").forEach(t => t.classList.toggle("active", t.dataset.mtab === "chat"));
      app.classList.add("m-tab-chat");
      return;
    }
    app.classList.add("m-tab-" + state.mobileTab);
  }

  // ---------- event wiring ----------
  function autoResize(ta) {
    ta.style.height = "auto";
    ta.style.height = Math.min(200, ta.scrollHeight) + "px";
  }

  
  // ===== TOOLBAR OVERFLOW MENU =====
  function wireOverflow(btnSel, menuSel) {
    const btn = $(btnSel);
    const menu = $(menuSel);
    if (!btn || !menu) return;
    // Move menu out of composer/preview-head — those have backdrop-filter/transform
    // which create a containing block for position:fixed children, so the menu
    // would otherwise stay clipped inside its parent. Re-parenting to <body>
    // makes the viewport its containing block, so JS coords actually work.
    if (menu.parentNode !== document.body) {
      document.body.appendChild(menu);
    }
    function positionMenu() {
      const r = btn.getBoundingClientRect();
      const mw = menu.offsetWidth || 180;
      const mh = menu.offsetHeight || 200;
      const margin = 8;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      let top = r.top - mh - 6;
      if (top < margin) top = r.bottom + 6;
      if (top + mh > vh - margin) top = Math.max(margin, vh - mh - margin);
      let left = r.left;
      if (left + mw > vw - margin) left = vw - mw - margin;
      if (left < margin) left = margin;
      menu.style.top = `${Math.round(top)}px`;
      menu.style.left = `${Math.round(left)}px`;
    }
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const willOpen = !menu.classList.contains("open");
      if (willOpen) {
        menu.classList.add("open");
        // measure AFTER it's displayed, then reposition
        positionMenu();
        // re-measure on next frame in case fonts/content shifted size
        requestAnimationFrame(positionMenu);
      } else {
        menu.classList.remove("open");
      }
    });
    menu.addEventListener("click", (e) => {
      if (e.target.closest(".mm-item, .chip")) menu.classList.remove("open");
    });
    document.addEventListener("click", (e) => {
      if (!menu.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {
        menu.classList.remove("open");
      }
    });
    window.addEventListener("resize", () => {
      if (menu.classList.contains("open")) positionMenu();
    });
    window.addEventListener("scroll", () => {
      if (menu.classList.contains("open")) positionMenu();
    }, true);
  }
  function initMobileToolbarOverflow() {
    wireOverflow("#btn-toolbar-overflow", "#toolbar-overflow-menu");
    wireOverflow("#btn-preview-overflow", "#preview-overflow-menu");
  }

  function wireEvents() {
    $("#btn-new-chat").addEventListener("click", newChat);
    $("#btn-settings").addEventListener("click", openSettings);
    $("#btn-close-settings").addEventListener("click", closeSettings);
    $("#drawer-scrim").addEventListener("click", closeSettings);
    const openFaq = () => { $("#faq-scrim").classList.add("open"); $("#faq-modal").classList.add("open"); };
    const closeFaq = () => { $("#faq-scrim").classList.remove("open"); $("#faq-modal").classList.remove("open"); };
    $("#btn-faq")?.addEventListener("click", openFaq);
    $("#btn-close-faq")?.addEventListener("click", closeFaq);
    $("#faq-scrim")?.addEventListener("click", closeFaq);
    $("#btn-save-settings").addEventListener("click", collectAndSaveSettings);
    $("#sw-dark").addEventListener("click", e => e.currentTarget.classList.toggle("on"));
    $("#sw-desktop-enabled")?.addEventListener("click", e => e.currentTarget.classList.toggle("on"));
    $("#btn-desktop-panic")?.addEventListener("click", async () => {
      try {
        await api("/api/desktop/panic", { method: "POST" });
        toast("desktop automation panicked — all actions blocked", "warn", 4000);
        refreshDesktopStatus();
      } catch (e) { toast("panic failed: " + e.message, "error"); }
    });
    $("#btn-desktop-resume")?.addEventListener("click", async () => {
      try {
        await api("/api/desktop/resume", { method: "POST" });
        toast("desktop automation resumed", "ok", 2500);
        refreshDesktopStatus();
      } catch (e) { toast("resume failed: " + e.message, "error"); }
    });
    $("#sw-web").addEventListener("click", e => e.currentTarget.classList.toggle("on"));
    $("#sw-thinking")?.addEventListener("click", e => e.currentTarget.classList.toggle("on"));
    const refreshModels = async () => {
      await loadModels();
      populateSettingsForm();
      renderModelPill();
    };
    $("#btn-refresh-models").addEventListener("click", async () => {
      const btn = $("#btn-refresh-models");
      btn.disabled = true;
      try { await refreshModels(); } finally { btn.disabled = false; }
    });
    $("#btn-rescan-models-dir")?.addEventListener("click", async () => {
      const btn = $("#btn-rescan-models-dir");
      const path = ($("#set-models-dir")?.value || "").trim();
      if (!path) { toast("pick a models folder first", "warn"); return; }
      btn.disabled = true;
      try {
        await api("/api/models/scan-dir", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ path }),
        });
        await refreshModels();
        toast("models folder scanned", "ok", 2000);
      } catch (e) {
        toast("scan failed: " + (e.message || e), "error");
      } finally { btn.disabled = false; }
    });
    $("#btn-browse-models-dir")?.addEventListener("click", async () => {
      const btn = $("#btn-browse-models-dir");
      btn.disabled = true;
      try {
        const r = await api("/api/browse-folder", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ title: "Pick models folder" }),
        });
        if (!r.path) return;
        $("#set-models-dir").value = r.path;
        await api("/api/models/scan-dir", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ path: r.path }),
        });
        await refreshModels();
        toast("models folder set", "ok", 2000);
      } catch (e) {
        toast("browse failed: " + (e.message || e), "error");
      } finally { btn.disabled = false; }
    });
    $("#set-models-dir")?.addEventListener("change", async (e) => {
      const path = (e.target.value || "").trim();
      if (!path) return;
      try {
        await api("/api/models/scan-dir", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ path }),
        });
        await refreshModels();
      } catch (err) {
        toast("scan failed: " + (err.message || err), "error");
      }
    });
    $("#model-pill").addEventListener("click", openSettings);
    $("#set-model").addEventListener("change", async () => {
      const sel = $("#set-model");
      const m = sel.value;
      if (!m) return;
      const hint = $("#set-model-hint");
      const prev = hint?.textContent;
      sel.disabled = true;
      if (hint) hint.textContent = "loading model into llama-server...";
      try {
        await api("/api/models/load", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ path: m }),
        });
        await refreshModels();
        toast("model loaded", "ok", 2500);
      } catch (e) {
        if (hint) hint.textContent = prev || "";
        toast("load failed: " + (e.message || e), "error", 6000);
      } finally {
        sel.disabled = false;
      }
    });
    $("#btn-sysctx-rescan").addEventListener("click", rescanSystemContext);
    $("#btn-sysctx-save").addEventListener("click", saveSystemContext);
    $("#btn-theme").addEventListener("click", async () => {
      const dark = state.settings.theme !== "dark";
      await saveSettings({ theme: dark ? "dark" : "light" });
      applyTheme(dark);
    });
    $("#btn-send").addEventListener("click", send);
    $("#btn-stop").addEventListener("click", stopStreaming);
    $("#composer-input").addEventListener("input", e => autoResize(e.target));
    $("#composer-input").addEventListener("keydown", e => {
      if (e.key !== "Enter") return;
      if (e.shiftKey) return; // newline
      e.preventDefault();
      send();
    });

    // image attach: click button, paste, drop
    $("#btn-attach-image")?.addEventListener("click", () => $("#file-image").click());
    $("#file-image")?.addEventListener("change", async (e) => {
      await addImageFiles(Array.from(e.target.files || []));
      e.target.value = "";
    });
    $("#composer-input").addEventListener("paste", (e) => {
      const items = Array.from(e.clipboardData?.items || []);
      const files = items.filter(i => i.kind === "file" && i.type.startsWith("image/")).map(i => i.getAsFile()).filter(Boolean);
      if (files.length) { e.preventDefault(); addImageFiles(files); }
    });
    const composerEl = document.querySelector(".composer");
    if (composerEl) {
      composerEl.addEventListener("dragover", (e) => { e.preventDefault(); composerEl.classList.add("drag-over"); });
      composerEl.addEventListener("dragleave", () => composerEl.classList.remove("drag-over"));
      composerEl.addEventListener("drop", async (e) => {
        e.preventDefault();
        composerEl.classList.remove("drag-over");
        const files = Array.from(e.dataTransfer?.files || []).filter(f => f.type.startsWith("image/"));
        if (files.length) addImageFiles(files);
      });
    }

    // composer draft auto-save
    $("#composer-input").addEventListener("input", (e) => {
      autoResize(e.target);
      if (state.chatId) {
        localStorage.setItem("accuretta:draft:" + state.chatId, e.target.value);
      }
    });

    // mode chips
    $$('[data-mode]').forEach(b => {
      b.addEventListener("click", () => {
        state.mode = b.dataset.mode;
        $$('[data-mode]').forEach(x => x.classList.remove("on"));
        b.classList.add("on");
      });
    });

    // IDE toolbar: Tailwind CDN toggle
    $("#toggle-tailwind")?.addEventListener("click", async () => {
      const next = !state.settings.use_tailwind_cdn;
      await saveSettings({ use_tailwind_cdn: next });
      reflectIdeToggles();
      if (state.currentHtml) renderPreview();
      toast(next ? "Tailwind CDN will be injected into the preview" : "Tailwind CDN off", "info", 2200, "ide-tw");
    });

    // IDE toolbar: multi-file output toggle
    $("#toggle-multifile")?.addEventListener("click", async () => {
      const next = !state.settings.ide_multifile;
      await saveSettings({ ide_multifile: next });
      reflectIdeToggles();
      toast(next ? "Model will emit multi-file folder structure" : "Single-file mode", "info", 2200, "ide-mf");
    });

    // Network: quick prompt insert for "scan this machine"
    $("#quick-netscan-mothership")?.addEventListener("click", () => {
      const ta = $("#composer-input");
      if (!ta) return;
      const tmpl = "Run a network snapshot on this machine (call network_snapshot). Then: list the active TCP connections grouped by process, flag anything that looks unusual (unknown processes, connections to suspicious IPs/domains, unexpected open ports), summarize the recent DNS queries, and tell me whether anything warrants a closer look.";
      const cur = ta.value.trim();
      ta.value = cur ? cur + "\n\n" + tmpl : tmpl;
      ta.focus();
      autoResize(ta);
      $("#toolbar-overflow-menu")?.classList.remove("open");
    });
    $("#quick-netscan-device")?.addEventListener("click", () => {
      $("#toolbar-overflow-menu")?.classList.remove("open");
      toast("Sniff-this-device needs a netagent on the remote box — coming soon.", "info", 3500, "netagent-soon");
    });

    // preview: screenshot the iframe to PNG
    $("#btn-screenshot")?.addEventListener("click", screenshotPreview);

    // preview: export the current preview as a zip (or single .html if no companions)
    $("#btn-export-project")?.addEventListener("click", exportProjectZip);

    // preview: review this UI — capture and attach to composer
    $("#btn-review-ui")?.addEventListener("click", reviewUiAttach);

    // preview toggle
    $("#btn-view-preview").addEventListener("click", () => {
      state.view = "preview";
      $("#btn-view-preview").classList.add("active");
      $("#btn-view-code").classList.remove("active");
      renderPreview();
    });
    $("#btn-view-code").addEventListener("click", () => {
      state.view = "code";
      $("#btn-view-code").classList.add("active");
      $("#btn-view-preview").classList.remove("active");
      renderPreview();
    });
    $("#btn-refresh").addEventListener("click", renderPreview);
    $("#btn-open-new").addEventListener("click", () => {
      if (!state.activeVersion) return;
      window.open(`/api/versions/${state.chatId}/${state.activeVersion}`, "_blank");
    });
    $("#btn-close-preview").addEventListener("click", () => app.classList.add("preview-collapsed"));

    // preview pane resize drag
    const resizer = $("#preview-resizer");
    if (resizer) {
      let dragging = false;
      const endDrag = () => {
        if (!dragging) return;
        dragging = false;
        resizer.classList.remove("dragging");
        app.classList.remove("resizing");
        document.body.style.userSelect = "";
        try { resizer.releasePointerCapture?.(resizer._pid); } catch {}
        localStorage.setItem("accuretta:preview-w", app.style.getPropertyValue("--preview-w"));
      };
      resizer.addEventListener("pointerdown", (e) => {
        dragging = true;
        resizer._pid = e.pointerId;
        try { resizer.setPointerCapture(e.pointerId); } catch {}
        resizer.classList.add("dragging");
        app.classList.add("resizing");
        document.body.style.userSelect = "none";
        e.preventDefault();
      });
      resizer.addEventListener("pointermove", (e) => {
        if (!dragging) return;
        const w = Math.max(280, Math.min(window.innerWidth - 280, window.innerWidth - e.clientX));
        app.style.setProperty("--preview-w", w + "px");
      });
      resizer.addEventListener("pointerup", endDrag);
      resizer.addEventListener("pointercancel", endDrag);
      window.addEventListener("blur", endDrag);
      const saved = localStorage.getItem("accuretta:preview-w");
      if (saved) app.style.setProperty("--preview-w", saved);
    }
    $("#pull-tab").addEventListener("click", () => app.classList.remove("preview-collapsed"));
    $("#btn-toggle-preview").addEventListener("click", () => app.classList.toggle("preview-collapsed"));

    // sidebar toggles
    $("#btn-toggle-sidebar").addEventListener("click", () => app.classList.add("sidebar-collapsed"));
    $("#btn-toggle-sidebar-m").addEventListener("click", () => {
      if (isMobile()) {
        state.mobileTab = "sessions";
        applyMobileTab();
      } else {
        app.classList.toggle("sidebar-collapsed");
      }
    });
    $("#pull-tab-left").addEventListener("click", () => app.classList.remove("sidebar-collapsed"));

    // workspace add
    $("#btn-ws-add-toggle").addEventListener("click", () => {
      $("#ws-add").classList.toggle("hidden");
      $("#ws-input").focus();
    });
    $("#ws-add-btn").addEventListener("click", addWorkspaceFolder);
    $("#ws-browse-btn").addEventListener("click", async () => {
      const btn = $("#ws-browse-btn");
      btn.disabled = true;
      try {
        const r = await api("/api/browse-folder", { method: "POST", headers: {"Content-Type": "application/json"}, body: "{}" });
        if (r.path) {
          $("#ws-input").value = r.path;
          await addWorkspaceFolder();
        }
      } finally { btn.disabled = false; }
    });
    $("#ws-input").addEventListener("keydown", e => {
      if (e.key === "Enter") { e.preventDefault(); addWorkspaceFolder(); }
    });

    // mobile tabs (legacy bottom bar, still wired for desktop testing)
    $$('.mobile-tab').forEach(t => t.addEventListener("click", () => {
      state.mobileTab = t.dataset.mtab;
      applyMobileTab();
    }));

    // mobile top-right overflow menu
    const mm = $("#mobile-menu");
    const mmScrim = $("#mobile-menu-scrim");
    const mmBtn = $("#btn-mobile-menu");
    const closeMM = () => { mm.classList.remove("open"); mmScrim.classList.remove("open"); };
    const openMM = () => {
      const dark = document.documentElement.getAttribute("data-theme") !== "light";
      const lbl = $("#mm-theme-label");
      if (lbl) lbl.textContent = dark ? "Light mode" : "Dark mode";
      mm.classList.add("open"); mmScrim.classList.add("open");
    };
    mmBtn?.addEventListener("click", (e) => {
      e.stopPropagation();
      mm.classList.contains("open") ? closeMM() : openMM();
    });
    mmScrim?.addEventListener("click", closeMM);
    $$(".mm-item").forEach(it => it.addEventListener("click", () => {
      const a = it.dataset.mm;
      closeMM();
      if (a === "theme") { $("#btn-theme").click(); return; }
      if (a === "settings") { openSettings(); return; }
      if (a === "faq") { $("#btn-faq")?.click(); return; }
      if (a === "chat" || a === "sessions" || a === "approvals") {
        state.mobileTab = a;
        applyMobileTab();
      }
    }));

    // responsive
    window.addEventListener("resize", () => {
      document.body.classList.toggle("is-mobile", isMobile());
    });

    // ----- command palette -----
    $("#btn-palette")?.addEventListener("click", openPalette);
    const palInput = $("#palette-input");
    if (palInput) {
      palInput.addEventListener("input", (e) => refreshPaletteList(e.target.value));
      palInput.addEventListener("keydown", (e) => {
        if (e.key === "Escape") { e.preventDefault(); closePalette(); }
        else if (e.key === "ArrowDown") { e.preventDefault(); paletteMove(1); }
        else if (e.key === "ArrowUp") { e.preventDefault(); paletteMove(-1); }
        else if (e.key === "Enter") { e.preventDefault(); paletteCommit(); }
      });
    }
    $("#palette-scrim")?.addEventListener("click", closePalette);

    // ⌘K / Ctrl+K anywhere
    window.addEventListener("keydown", (e) => {
      const isCmd = e.metaKey || e.ctrlKey;
      if (isCmd && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        if (state.palette && state.palette.open) closePalette();
        else openPalette();
      }
    });

    // ----- per-session desktop kill switch -----
    $("#btn-session-desktop")?.addEventListener("click", toggleSessionDesktop);

    // ----- preview extras -----
    $("#btn-save-snapshot")?.addEventListener("click", saveSnapshot);
    $("#btn-copy-dataurl")?.addEventListener("click", copyPreviewAsDataUrl);

    // ----- console pane -----
    $("#btn-toggle-console")?.addEventListener("click", () => toggleConsolePane());
    $("#btn-console-clear")?.addEventListener("click", clearConsole);
    $("#btn-console-close")?.addEventListener("click", () => toggleConsolePane(false));

    // ----- viewport presets -----
    $$(".vp-btn").forEach(b => b.addEventListener("click", () => applyViewport(b.dataset.vp)));

    // ----- memories panel -----
    $("#btn-mem-refresh")?.addEventListener("click", loadMemories);
    $("#btn-mem-clear")?.addEventListener("click", async () => {
      if (!confirm("Forget all memories? This cannot be undone.")) return;
      try {
        await api("/api/memories/clear", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      } catch (e) { toast("clear failed: " + e.message, "error"); }
    });
    $("#btn-mem-add")?.addEventListener("click", addMemoryFromInput);
    $("#mem-add-text")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); addMemoryFromInput(); }
    });

    // ----- mobile toolbar overflow -----
    initMobileToolbarOverflow();
  }

  // Periodic refresh for real-time updates
  setInterval(() => {
    if (document.visibilityState === "visible") {
      renderCtxGauge();
    }
  }, 3000);

  // kick off
  loadApprovals();
  boot().catch(e => {
    console.error(e);
    alert("boot error: " + e.message);
  });
})();
