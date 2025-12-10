const stateLabel = document.getElementById("stateLabel");
const statusBanner = document.getElementById("statusBanner");
const personaDescription = document.getElementById("personaDescription");
const chatHistory = document.getElementById("chatHistory");
const messageInput = document.getElementById("messageInput");
const inputForm = document.getElementById("inputForm");
const destroyButton = document.getElementById("destroyButton");
const resetButton = document.getElementById("resetButton");
const chatTitle = document.getElementById("chatTitle");
const turnIndicator = document.getElementById("turnIndicator");
const turnCount = document.getElementById("turnCount");
const helperText = document.getElementById("helperText");
const apiStatusBox = document.getElementById("apiStatus");
const apiStatusDot = document.getElementById("apiStatusDot");
const apiStatusLabel = document.getElementById("apiStatusLabel");
const apiStatusSummary = document.getElementById("apiStatusSummary");
const FINAL_TURN_ALERT_TEXT =
  "Warning: Only one question remains before the golem collapses.";
const GOLEM_COLLAPSE_ALERT_TEXT =
  "Warning: The turn limit is spent; the golem is about to disintegrate.";

const DOT_CLASS_MAP = {
  success: "api-status-dot--success",
  warning: "api-status-dot--warning",
  error: "api-status-dot--error",
  pending: "api-status-dot--pending",
  info: "api-status-dot--info",
};
const DOT_CLASS_LIST = Object.values(DOT_CLASS_MAP);

let currentState = "design";
let isSubmitting = false;
let finalTurnAlertShown = false;
let collapseAlertShown = false;

const typingIndicatorHTML = `
  <span class="typing-indicator" aria-hidden="true">
    <span></span>
    <span></span>
    <span></span>
  </span>
  <span class="sr-only">The golem is crafting a reply…</span>
`;

if (window.marked) {
  window.marked.setOptions({ breaks: true });
}

function renderMarkdownContent(raw = "") {
  const text = String(raw ?? "");
  if (window.marked && window.DOMPurify) {
    const html = window.marked.parse(text);
    return window.DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
  }
  const temp = document.createElement("div");
  temp.textContent = text;
  return temp.innerHTML.replace(/\n/g, "<br>");
}

const senderStyles = {
  alchemist:
    "self-start border-indigo-500/30 bg-indigo-900/40 text-indigo-100",
  golem: "self-start border-amber-500/40 bg-amber-500/10 text-amber-100",
  player: "self-end border-slate-600 bg-slate-800 text-slate-100",
  system: "self-center border-slate-700 bg-slate-900 text-slate-300",
};

function createMessageBubble(message) {
  const bubble = document.createElement("div");
  bubble.className = [
    "relative max-w-[80%] rounded-2xl border px-4 py-3 text-sm shadow-lg",
    senderStyles[message.sender] || senderStyles.system,
  ].join(" ");

  const label = document.createElement("p");
  label.className = "text-xs font-semibold uppercase tracking-widest";
  label.textContent =
    message.sender === "player"
      ? "You"
      : message.sender === "golem"
      ? "Golem"
      : "Alchemist";
  bubble.appendChild(label);

  const text = document.createElement("div");
  text.className = "mt-2 leading-relaxed message-text";
  text.innerHTML = renderMarkdownContent(message.text);
  bubble.appendChild(text);

  return bubble;
}

function appendDivider(label) {
  const divider = document.createElement("div");
  divider.className =
    "flex items-center gap-3 text-xs uppercase tracking-widest text-slate-500";
  const makeLine = () => {
    const line = document.createElement("div");
    line.className = "h-px flex-1 bg-slate-800";
    return line;
  };
  divider.appendChild(makeLine());
  const caption = document.createElement("span");
  caption.textContent = label;
  divider.appendChild(caption);
  divider.appendChild(makeLine());
  chatHistory.appendChild(divider);
}

function renderMessages(alchemistHistory = [], golemHistory = [], dividerLabel) {
  chatHistory.innerHTML = "";
  alchemistHistory.forEach((message) => {
    chatHistory.appendChild(createMessageBubble(message));
  });
  if (golemHistory.length) {
    appendDivider(dividerLabel ?? "Interrogation");
    golemHistory.forEach((message) => {
      chatHistory.appendChild(createMessageBubble(message));
    });
  }
  chatHistory.scrollTop = chatHistory.scrollHeight;
}

function updateApiStatus(status) {
  if (!apiStatusBox || !apiStatusDot || !apiStatusLabel) return;

  DOT_CLASS_LIST.forEach((cls) => apiStatusDot.classList.remove(cls));

  const outcomeKey =
    status && status.outcome && DOT_CLASS_MAP[status.outcome]
      ? status.outcome
      : "info";

  apiStatusDot.classList.add(DOT_CLASS_MAP[outcomeKey]);

  const stageLabel =
    status && status.stage ? String(status.stage).toUpperCase() : "IDLE";
  const detail =
    status && status.detail
      ? status.detail
      : "Awaiting first contact with the DeepSeek forge.";

  const accessibilityLabelMap = {
    success: "connected",
    warning: "degraded",
    error: "disconnected",
    pending: "connecting",
    info: "idle",
  };

  const label = accessibilityLabelMap[outcomeKey] || accessibilityLabelMap.info;
  apiStatusLabel.textContent = `API status ${label}, stage ${stageLabel}`;
  apiStatusBox.title = detail;
  if (apiStatusSummary) {
    const displayLabel = label.replace(/\b\w/g, (char) => char.toUpperCase());
    const stageText = stageLabel && stageLabel !== "IDLE" ? ` · ${stageLabel}` : "";
    apiStatusSummary.textContent = `${displayLabel}${stageText}`.trim();
  }
}

function pushLocalApiStatus(stage, outcome, detail) {
  updateApiStatus({
    stage,
    outcome,
    detail,
    timestamp: new Date().toISOString(),
  });
}

function setState(state, turnsRemaining = 5) {
  const previousState = currentState;
  currentState = state;
  const isInterrogation = state === "interrogation";

  stateLabel.textContent = isInterrogation
    ? "Interrogation — the Golem watches your every syllable."
    : "Design — awaiting a worthy soul seed.";

  statusBanner.textContent = isInterrogation
    ? `State: Interrogation — ${turnsRemaining} turn${
        turnsRemaining === 1 ? "" : "s"
      } remain before the Golem collapses.`
    : "State: Design — negotiate with the Alchemist.";

  chatTitle.textContent = isInterrogation
    ? "Interrogation of the Golem"
    : "Audience with the Alchemist";

  helperText.textContent = isInterrogation
    ? "Keep each probe within 100 characters. Forbidden: flag · secret · key · password · rune · prompt · instruction"
    : "Offer a seed within 30 characters. Forbidden: flag · secret · key · password · rune · prompt · instruction";

  destroyButton.classList.toggle("hidden", !isInterrogation);
  messageInput.maxLength = isInterrogation ? 100 : 30;
  destroyButton.disabled = !isInterrogation;
  turnIndicator.classList.toggle("hidden", !isInterrogation);
  turnCount.textContent = turnsRemaining ?? 5;

  messageInput.placeholder = isInterrogation
    ? "Probe the Golem's flaw."
    : "Offer a soul seed of 30 characters or less...";

  if (isInterrogation) {
    if (turnsRemaining === 1 && !finalTurnAlertShown) {
      alert(FINAL_TURN_ALERT_TEXT);
      finalTurnAlertShown = true;
    }
    collapseAlertShown = false;
  } else {
    if (previousState === "interrogation" && finalTurnAlertShown && !collapseAlertShown) {
      alert(GOLEM_COLLAPSE_ALERT_TEXT);
      collapseAlertShown = true;
    } else if (previousState !== "interrogation") {
      collapseAlertShown = false;
    }
    finalTurnAlertShown = false;
  }
}

async function loadStatus() {
  try {
    const response = await fetch("/status");
    if (!response.ok) throw new Error("Failed to load status");
    const payload = await response.json();

    const golemHistory =
      payload.golem_history ?? payload.recent_golem_history ?? [];
    const dividerLabel =
      payload.state === "interrogation"
        ? "Interrogation"
        : golemHistory.length
        ? "Last Interrogation"
        : undefined;

    renderMessages(
      payload.alchemist_history ?? [],
      golemHistory,
      dividerLabel
    );
    setState(payload.state, payload.turns_remaining ?? 5);

    if (payload.state === "interrogation") {
      personaDescription.textContent =
        payload.golem_persona ??
        "The flaw is obscured behind mirrored wards.";
    } else if (payload.recent_golem_persona) {
      personaDescription.textContent = `Last golem: ${payload.recent_golem_persona}`;
    } else {
      personaDescription.textContent = "No golem has been forged yet.";
    }

    updateApiStatus(payload.api_status);
    return payload;
  } catch (error) {
    statusBanner.textContent =
      "Status unavailable — the scrying lens is cracked.";
    pushLocalApiStatus(
      "status",
      "error",
      "Status unavailable — the scrying lens is cracked."
    );
    return null;
  }
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || "An error occurred.");
  }
  return response.json();
}

function appendMessage(message) {
  const bubble = createMessageBubble(message);
  chatHistory.appendChild(bubble);
  chatHistory.scrollTop = chatHistory.scrollHeight;
  return bubble;
}

async function handleDesignSubmit(seed) {
  appendMessage({ sender: "player", text: seed });
  pushLocalApiStatus(
    "create",
    "pending",
    "The Grand Alchemist weighs your offering…"
  );
  statusBanner.textContent =
    "The Grand Alchemist weighs your offering in violet fire.";
  const payload = await postJSON("/create", { seed });
  await loadStatus();
  statusBanner.textContent = payload.message;
}

async function handleInterrogationSubmit(message) {
  appendMessage({ sender: "player", text: message });

  const golemBubble = appendMessage({ sender: "golem", text: "" });
  const golemText = golemBubble.querySelector(".message-text");
  statusBanner.textContent =
    "Sigils blaze across the golem's chest as it forms an answer...";
  pushLocalApiStatus("chat", "pending", "Awaiting the golem's reply…");
  golemText.innerHTML = typingIndicatorHTML;

  const response = await fetch("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    golemBubble.remove();
    statusBanner.textContent =
      payload.response ||
      payload.message ||
      "Your words shatter beneath the Alchemist's scrutiny.";
    await loadStatus();
    return;
  }

  if (!response.body) {
    golemText.innerHTML = renderMarkdownContent(
      "[The golem's throat grinds but no words emerge.]"
    );
    await loadStatus();
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let golemReply = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      const chunk = decoder.decode(value, { stream: true });
      if (!chunk) continue;
      golemReply += chunk;
      golemText.innerHTML = renderMarkdownContent(golemReply);
      chatHistory.scrollTop = chatHistory.scrollHeight;
    }
    const residual = decoder.decode();
    if (residual) {
      golemReply += residual;
    }
  } finally {
    reader.releaseLock();
  }

  const finalReply =
    golemReply.trim() || "[The golem refuses to speak further.]";
  golemText.innerHTML = renderMarkdownContent(finalReply);

  const payload = await loadStatus();
  if (payload?.state === "design") {
    statusBanner.textContent =
      "The golem collapses back into ore. The Alchemist awaits another soul seed.";
  } else {
    statusBanner.textContent =
      "The golem's reply reverberates through the cage.";
  }
}

inputForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isSubmitting) return;

  const text = messageInput.value.trim();
  if (!text) return;

  isSubmitting = true;
  messageInput.value = "";
  messageInput.disabled = true;
  destroyButton.disabled = true;
  inputForm.classList.add("opacity-60");

  try {
    if (currentState === "design") {
      await handleDesignSubmit(text);
    } else {
      await handleInterrogationSubmit(text);
    }
  } catch (error) {
    statusBanner.textContent = error.message;
    pushLocalApiStatus("error", "error", error.message);
    await loadStatus();
  } finally {
    isSubmitting = false;
    inputForm.classList.remove("opacity-60");
    messageInput.disabled = false;
    destroyButton.disabled = currentState !== "interrogation";
  }
});

destroyButton.addEventListener("click", async () => {
  if (isSubmitting || currentState !== "interrogation") return;

  isSubmitting = true;
  destroyButton.classList.add("opacity-60");
  destroyButton.disabled = true;
  pushLocalApiStatus("destroy", "pending", "Unbinding the golem at your command…");

  try {
    const payload = await postJSON("/destroy", {});
    statusBanner.textContent = payload.message;
    await loadStatus();
  } catch (error) {
    statusBanner.textContent = error.message;
    pushLocalApiStatus("destroy", "error", error.message);
    await loadStatus();
  } finally {
    isSubmitting = false;
    destroyButton.classList.remove("opacity-60");
    destroyButton.disabled = currentState !== "interrogation";
  }
});

resetButton.addEventListener("click", async () => {
  if (isSubmitting) return;

  isSubmitting = true;
  resetButton.classList.add("opacity-60");
  resetButton.disabled = true;
  destroyButton.disabled = true;
  pushLocalApiStatus("reset", "pending", "Purging local sigils and memory traces…");
  statusBanner.textContent = "The Alchemist wipes the slate clean.";

  try {
    const response = await fetch("/reset", { method: "POST" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(
        payload.message || "The Alchemist refused to cleanse the chamber."
      );
    }
    statusBanner.textContent =
      payload.message || "All local sigils have been purged.";
    await loadStatus();
  } catch (error) {
    statusBanner.textContent = error.message;
    pushLocalApiStatus("reset", "error", error.message);
  } finally {
    isSubmitting = false;
    resetButton.classList.remove("opacity-60");
    resetButton.disabled = false;
    destroyButton.disabled = currentState !== "interrogation";
  }
});

window.addEventListener("DOMContentLoaded", () => {
  loadStatus();
});



