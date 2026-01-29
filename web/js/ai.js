if (typeof window.requireAdmin === "function") {
  window.requireAdmin();
}

(function () {
  const el = (id) => document.getElementById(id);
  const STORAGE_PROMPT = "ai_creator_prompt";
  const previewSpinner = el("previewSpinner");
  const previewSpinnerText = el("previewSpinnerText");
  const previewPlaceholder = el("previewPlaceholder");
  const previewContent = el("previewContent");
  const refineSection = el("refineSection");
  const refineInput = el("refineInput");
  const refineBtn = el("refineBtn");
  const publishBtn = el("publishBtn");
  const refineStatus = el("refineStatus");
  const discardBtn = el("discardBtn");
  const workflowSummary = el("workflowSummary");
  const previewActions = el("previewActions");
  const refineToggle = el("previewBeforePublish");
  const refineToggleLabel = refineToggle ? refineToggle.closest("label") : null;
  const STORAGE_TESTING_MODE = "ai_creator_testing_mode";
  const testingToggle = el("testingModeToggle");
  const testingToggleLabel = el("testingModeToggleLabel");
  const testingBanner = el("testingModeBanner");
  const searchParams = new URLSearchParams(window.location.search || "");
  const allowTestingToggle = detectLocalHost() || ["1", "true", "on"].includes((searchParams.get("enableTesting") || "").toLowerCase());
  const REFRESH_GUARD_MESSAGE = "A preview is in progress. Refreshing now will discard it.";
  let testingMode = false;
  let lastResponseTesting = false;

  let lastYaml = "";
  let lastPromptValue = "";
  let runButtonLocked = false;
  const MIN_TESTING_PREVIEW_MS = 5000;
  let refineToggleStickyLock = false;

  const paramTesting = (searchParams.get("testingMode") || "").toLowerCase();
  if (["1", "true", "on", "yes"].includes(paramTesting)) {
    testingMode = true;
  } else if (["0", "false", "off"].includes(paramTesting)) {
    testingMode = false;
  } else if (allowTestingToggle) {
    try {
      const storedMode = localStorage.getItem(STORAGE_TESTING_MODE);
      testingMode = storedMode === "1" || storedMode === "true";
    } catch { testingMode = false; }
  }
  if (!allowTestingToggle) testingMode = false;

  function detectLocalHost() {
    try {
      const host = window.location.hostname || "";
      if (!host) return false;
      if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i.test(host)) return true;
      if (host === "::1" || host === "[::1]") return true;
      if (/\.local$/i.test(host)) return true;
      return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host);
    } catch {
      return false;
    }
  }

  function syncTestingBanner(serverState) {
    if (typeof serverState === "boolean") lastResponseTesting = serverState;
    const isActive = !!(testingMode || lastResponseTesting);
    if (testingBanner) testingBanner.classList.toggle("hidden", !isActive);
    if (testingToggle) {
      testingToggle.setAttribute("aria-pressed", testingMode ? "true" : "false");
      testingToggle.classList.toggle("testing-on", isActive);
    }
    if (testingToggleLabel) testingToggleLabel.textContent = isActive ? "Mocked Gemini" : "Gemini live";
  }

  function setTestingMode(next) {
    if (!allowTestingToggle) return;
    testingMode = !!next;
    try { localStorage.setItem(STORAGE_TESTING_MODE, testingMode ? "1" : "0"); } catch { }
    syncTestingBanner();
  }

  function setRefineToggleStickyLock(active) {
    refineToggleStickyLock = !!active;
    updateRefineToggleDisabled();
  }

  function updateRefineToggleDisabled() {
    const disabled = runButtonLocked || refineToggleStickyLock;
    if (refineToggle) {
      refineToggle.disabled = disabled;
      refineToggle.setAttribute("aria-disabled", disabled ? "true" : "false");
    }
    if (refineToggleLabel) {
      refineToggleLabel.classList.toggle("form-toggle-disabled", disabled);
    }
  }

  function nowMs() {
    if (typeof performance !== "undefined" && typeof performance.now === "function") {
      return performance.now();
    }
    return Date.now();
  }

  function indentLen(line) {
    let count = 0;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (ch === " ") count += 1;
      else if (ch === "\t") count += 2;
      else break;
    }
    return count;
  }

  function fixPreBlockIndentation(text) {
    if (!text) return "";
    const lines = text.split(/\r?\n/);
    const blockRe = /^(?<indent>[ \t]*)(?:-[ \t]+)?[^#\n]*:\s*[|>][0-9+-]*\s*$/;
    const out = [];
    let inBlock = false;
    let inPre = false;
    let baseIndent = 0;
    let contentIndent = null;
    let i = 0;

    while (i < lines.length) {
      let line = lines[i];
      if (!inBlock) {
        out.push(line);
        const match = line.match(blockRe);
        if (match) {
          inBlock = true;
          inPre = false;
          const indentText = match.groups ? match.groups.indent : (match[1] || "");
          baseIndent = indentLen(indentText);
          contentIndent = null;
        }
        i += 1;
        continue;
      }

      if (contentIndent === null && line.trim()) {
        const indent = indentLen(line);
        contentIndent = indent > baseIndent ? indent : baseIndent + 2;
      }

      const lineHasPre = /<\s*pre\b/i.test(line);
      const lineHasPreEnd = /<\/\s*pre\s*>/i.test(line);
      const isPreRelated = inPre || lineHasPre || lineHasPreEnd;

      const indent = indentLen(line);
      if (line.trim() && indent <= baseIndent && !isPreRelated) {
        inBlock = false;
        inPre = false;
        contentIndent = null;
        continue;
      }

      if (isPreRelated && line.trim()) {
        const targetIndent = contentIndent == null ? baseIndent + 2 : contentIndent;
        if (indent < targetIndent) {
          line = " ".repeat(targetIndent) + line.replace(/^[ \t]*/, "");
        }
      }

      out.push(line);

      const preStarts = (line.match(/<\s*pre\b/gi) || []).length;
      const preEnds = (line.match(/<\/\s*pre\s*>/gi) || []).length;
      if (preStarts > preEnds) inPre = true;
      else if (preEnds > preStarts) inPre = false;

      i += 1;
    }

    return out.join("\n");
  }

  function cleanGeminiYaml(text) {
    if (typeof window.cleanGeminiYaml === "function") return window.cleanGeminiYaml(text);
    if (text == null) return "";
    return String(text).replace(/\[cite_start\]/g, "");
  }

  async function ensureTestingDelay(startedAt, testingActive) {
    if (!testingActive) return;
    const elapsed = nowMs() - startedAt;
    if (elapsed >= MIN_TESTING_PREVIEW_MS) return;
    await new Promise((resolve) => setTimeout(resolve, MIN_TESTING_PREVIEW_MS - elapsed));
  }

  function setStatus(message, tone) {
    const statusEl = el("statusText");
    if (!statusEl) return;
    statusEl.textContent = message || "";
    statusEl.classList.remove("text-slate-500", "text-red-600", "text-green-600");
    if (tone === "error") statusEl.classList.add("text-red-600");
    else if (tone === "success") statusEl.classList.add("text-green-600");
    else statusEl.classList.add("text-slate-500");
  }

  function serializePayload() {
    return {
      prompt: (el("prompt")?.value || "").trim(),
      teamId: el("teamSelect")?.value ? Number(el("teamSelect").value) : null,
      folderId: el("folderId")?.value ? Number(el("folderId").value) : null,
      publish: !!el("publish")?.checked,
    };
  }

  function startPreviewLoading(message) {
    if (previewSpinner) previewSpinner.classList.remove("hidden");
    if (previewSpinnerText) previewSpinnerText.textContent = message || "Building preview…";
    if (previewPlaceholder) {
      previewPlaceholder.textContent = message || "Building preview…";
      previewPlaceholder.classList.remove("hidden", "text-red-600");
      previewPlaceholder.classList.add("text-slate-500");
    }
    if (previewContent) {
      previewContent.innerHTML = "";
      previewContent.classList.add("hidden");
    }
  }

  function showPreviewMessage(message, isError) {
    if (previewSpinner) previewSpinner.classList.add("hidden");
    if (previewPlaceholder) {
      previewPlaceholder.textContent = message || "";
      previewPlaceholder.classList.remove("hidden");
      previewPlaceholder.classList.toggle("text-red-600", !!isError);
      previewPlaceholder.classList.toggle("text-slate-500", !isError);
    }
    if (previewContent) previewContent.classList.add("hidden");
  }

  function renderPreviewFromYaml(yamlText) {
    if (!previewContent) return;
    const cleaned = cleanGeminiYaml(String(yamlText || ""));
    const sanitized = fixPreBlockIndentation(cleaned);
    if (!sanitized || !sanitized.trim()) {
      showPreviewMessage("No preview available yet.");
      return;
    }
    if (!window.jsyaml || typeof window.jsyaml.loadAll !== "function") {
      showPreviewMessage("Preview unavailable (missing YAML parser).", true);
      return;
    }
    const docs = [];
    try {
      window.jsyaml.loadAll(sanitized, (doc) => {
        if (doc) docs.push(doc);
      });
    } catch (err) {
      showPreviewMessage("Preview unavailable (YAML parse error).", true);
      return;
    }

    const guides = [];
    docs.forEach((raw) => {
      if (!raw || typeof raw !== "object") return;
      const guide = raw.guide && typeof raw.guide === "object" ? raw.guide : raw;
      if (!guide || typeof guide !== "object" || !guide.firstStep) return;
      guides.push(window.createGuidePreviewCard(guide, guides.length + 1));
    });

    if (!guides.length) {
      showPreviewMessage("No guides found in YAML.");
      return;
    }

    previewContent.innerHTML = "";
    guides.forEach((card) => previewContent.appendChild(card));
    if (previewSpinner) previewSpinner.classList.add("hidden");
    if (previewPlaceholder) previewPlaceholder.classList.add("hidden");
    previewContent.classList.remove("hidden");
  }

  function setRunButtonDisabled(locked) {
    runButtonLocked = locked;
    const btn = el("runBtn");
    if (!btn) return;
    btn.disabled = locked;
    btn.classList.toggle("opacity-70", locked);
    btn.classList.toggle("cursor-not-allowed", locked);
    const promptEl = el("prompt");
    if (promptEl) {
      if (locked) {
        promptEl.setAttribute("disabled", "disabled");
        promptEl.classList.add("prompt-locked", "cursor-not-allowed");
      } else {
        promptEl.removeAttribute("disabled");
        promptEl.classList.remove("prompt-locked", "cursor-not-allowed");
      }
    }
    updateRefineToggleDisabled();
    updateBeforeUnloadGuard();
  }

  function showRefineSection() {
    if (refineSection) refineSection.classList.remove("hidden");
    if (previewActions) previewActions.classList.remove("hidden");
    if (refineStatus) {
      refineStatus.textContent = "Refine the preview or Validate & Publish when ready.";
      refineStatus.classList.remove("text-red-600", "text-green-600");
      refineStatus.classList.add("text-slate-500");
    }
    if (refineInput) {
      try { refineInput.focus({ preventScroll: false }); } catch { refineInput.focus(); }
    }
    queueRefineScroll();
    setRunButtonDisabled(true);
    setRefineToggleStickyLock(true);
    updateBeforeUnloadGuard();
  }

  function hideRefineSection() {
    if (refineSection) refineSection.classList.add("hidden");
    if (previewActions) previewActions.classList.add("hidden");
    if (refineStatus) refineStatus.textContent = "";
    if (refineInput) refineInput.value = "";
    setRunButtonDisabled(false);
    setRefineToggleStickyLock(false);
    updateBeforeUnloadGuard();
  }

  function shouldBlockNavigation() {
    const refineActive = !!(refineSection && !refineSection.classList.contains("hidden"));
    return !!runButtonLocked || refineActive;
  }

  function handleBeforeUnload(event) {
    if (!shouldBlockNavigation()) return;
    event.preventDefault();
    event.returnValue = REFRESH_GUARD_MESSAGE;
    return REFRESH_GUARD_MESSAGE;
  }

  function updateBeforeUnloadGuard() {
    if (shouldBlockNavigation()) {
      window.addEventListener("beforeunload", handleBeforeUnload);
    } else {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    }
  }

  function queueRefineScroll() {
    if (!refineSection) return;
    const scrollFn = () => {
      try {
        refineSection.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch {
        const rect = refineSection.getBoundingClientRect();
        const offset = rect.top + window.scrollY - 24;
        window.scrollTo({ top: offset, behavior: "smooth" });
      }
    };
    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(scrollFn);
    } else {
      setTimeout(scrollFn, 0);
    }
  }

  function setRefineStatus(message, tone = "info") {
    if (!refineStatus) return;
    refineStatus.textContent = message || "";
    refineStatus.classList.remove("text-red-600", "text-green-600", "text-slate-500");
    if (tone === "error") refineStatus.classList.add("text-red-600");
    else if (tone === "success") refineStatus.classList.add("text-green-600");
    else refineStatus.classList.add("text-slate-500");
  }

  async function submitAIRequest({
    previewOnly = false,
    baseYaml,
    refinePrompt,
    yamlOverride,
    button,
    spinnerMessage,
    statusMessage,
    showRefineUI = true,
  } = {}) {
    const payload = serializePayload();
    payload.prompt = (payload.prompt || lastPromptValue || "").trim();
    lastPromptValue = payload.prompt;
    payload.previewOnly = !!previewOnly;
    payload.testingMode = !!testingMode;
    if (baseYaml) payload.baseYaml = baseYaml;
    if (refinePrompt) payload.refinePrompt = refinePrompt;
    if (yamlOverride) payload.yamlOverride = yamlOverride;
    const requestStartedAt = nowMs();
    const expectedTesting = !!testingMode;

    const actionBtn = button || el("runBtn");
    if (actionBtn) {
      actionBtn.disabled = true;
      actionBtn.classList.add("opacity-70", "cursor-not-allowed");
    }
    setRunButtonDisabled(true);

    const spinnerText = typeof spinnerMessage === "string"
      ? spinnerMessage
      : (previewOnly ? "Building preview…" : "Validating & publishing…");
    const statusText = typeof statusMessage === "string"
      ? statusMessage
      : (previewOnly ? "Generating preview via Gemini…" : "Generating & building guide…");

    startPreviewLoading(spinnerText);
    setStatus(statusText, "info");

    let success = false;
    try {
      const res = await fetch(((window.BASE || window.DEFAULT_BACKEND || "").replace(/\/+$/, "")) + "/api/ai-guides/build", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      const responseTesting = typeof data?.testingMode === "boolean" ? !!data.testingMode : expectedTesting;
      await ensureTestingDelay(requestStartedAt, responseTesting);
      syncTestingBanner(data?.testingMode);
      const yamlOut = el("yamlOutput");
      const buildOut = el("buildOutput");

      if (!res.ok) {
        const detail = data?.detail || data || {};
        const msg = detail?.error || detail?.message || res.statusText || "Request failed";
        setStatus(msg, "error");
        const modelText = cleanGeminiYaml(detail?.modelText || "");
        if (yamlOut) yamlOut.textContent = modelText;
        if (buildOut) buildOut.textContent = JSON.stringify(detail, null, 2);
        if (modelText) {
          lastYaml = modelText;
          renderPreviewFromYaml(modelText);
        } else {
          showPreviewMessage("Preview unavailable. Please retry.", true);
        }
        return false;
      }

      const yamlText = cleanGeminiYaml(data?.yaml || "");
      if (yamlOut) yamlOut.textContent = yamlText;
      if (yamlText) lastYaml = yamlText;
      renderPreviewFromYaml(yamlText);

      if (payload.previewOnly) {
        if (showRefineUI) {
          if (buildOut) buildOut.textContent = "Preview only. Validate & Publish to create the guide.";
          showRefineSection();
          setStatus("Preview ready. Refine or publish when ready.", "success");
        }
      } else {
        if (buildOut) {
          if (data?.build) buildOut.textContent = JSON.stringify(data.build, null, 2);
          else buildOut.textContent = JSON.stringify(data, null, 2);
        }
        hideRefineSection();
        setStatus("Guide built successfully.", "success");
      }
      success = true;
    } catch (err) {
      await ensureTestingDelay(requestStartedAt, expectedTesting);
      setStatus("Request failed. Please retry.", "error");
      showPreviewMessage("Preview unavailable. Please retry.", true);
    } finally {
      syncTestingBanner();
      setRunButtonDisabled(payload.previewOnly && success);
      if (actionBtn) {
        const isRun = actionBtn.id === "runBtn";
        if (!(isRun && runButtonLocked)) {
          actionBtn.disabled = false;
          actionBtn.classList.remove("opacity-70", "cursor-not-allowed");
        }
      }
    }
    return success;
  }

  async function runCreator() {
    if (typeof window.validateRequired === "function") {
      const ok = window.validateRequired(["prompt", "teamSelect", "folderId"]);
      if (!ok) return;
    }
    const waitForPreview = !!el("previewBeforePublish")?.checked;
    const runBtn = el("runBtn");
    if (waitForPreview) {
      await submitAIRequest({ previewOnly: true, button: runBtn });
      return;
    }

    const previewOk = await submitAIRequest({
      previewOnly: true,
      button: runBtn,
      spinnerMessage: "Building guides…",
      statusMessage: "Building guides…",
      showRefineUI: false,
    });
    if (!previewOk) return;
    setStatus("Validating & publishing…", "info");
    await submitAIRequest({
      previewOnly: false,
      yamlOverride: lastYaml,
      button: runBtn,
      spinnerMessage: "Validating & publishing…",
      statusMessage: "Validating & publishing…",
    });
  }

  (window.onReady || function (fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
    } else {
      fn();
    }
  })(function () {
    if (testingToggle) {
      if (allowTestingToggle) {
        testingToggle.classList.remove("hidden");
        testingToggle.addEventListener("click", (e) => {
          e.preventDefault();
          setTestingMode(!testingMode);
        });
      } else {
        testingToggle.classList.add("hidden");
      }
    }
    syncTestingBanner();

    const form = el("creatorForm");
    if (form) form.addEventListener("submit", (e) => { e.preventDefault(); runCreator(); });
    const btn = el("runBtn");
    if (btn) btn.addEventListener("click", (e) => { e.preventDefault(); runCreator(); });

    const updateWorkflowSummary = () => {
      if (!workflowSummary) return;
      const waitForPreview = !!el("previewBeforePublish")?.checked;
      const publish = !!el("publish")?.checked;
      let summary = "Generate Preview → Build → ";
      if (waitForPreview) summary = "Generate Preview → Refine → Build → ";
      summary += publish ? "Publish" : "Push as draft";
      workflowSummary.textContent = summary;
    };
    ["previewBeforePublish", "publish"].forEach(id => {
      const checkbox = el(id);
      if (checkbox) checkbox.addEventListener("change", updateWorkflowSummary);
    });
    updateWorkflowSummary();

    try {
      const area = el("prompt");
      if (area) {
        const saved = localStorage.getItem(STORAGE_PROMPT);
        if (saved && !area.value) area.value = saved;
        area.addEventListener("input", () => {
          try { localStorage.setItem(STORAGE_PROMPT, area.value || ""); } catch { }
        });
      }
    } catch { /* ignore */ }

    const setupToggle = (buttonId, targetId) => {
      const button = el(buttonId);
      const target = el(targetId);
      if (!button || !target) return;
      button.addEventListener("click", () => {
        const hidden = target.classList.toggle("hidden");
        if (hidden) target.setAttribute("hidden", "hidden");
        else target.removeAttribute("hidden");
        button.textContent = hidden ? "Show" : "Hide";
      });
    };

    setupToggle("toggleYaml", "yamlOutput");
    setupToggle("toggleBuild", "buildOutput");

    if (typeof window.attachCopyButton === "function") {
      window.attachCopyButton({ buttonId: "copyYaml", sourceId: "yamlOutput", disableWhenEmpty: true });
      window.attachCopyButton({ buttonId: "copyBuild", sourceId: "buildOutput", disableWhenEmpty: true });
    }

    if (refineBtn) {
      refineBtn.addEventListener("click", async () => {
        if (!lastYaml) {
          setRefineStatus("Generate a preview before refining.", "error");
          return;
        }
        const instructions = (refineInput?.value || "").trim();
        if (!instructions) {
          setRefineStatus("Add instructions before refining.", "error");
          return;
        }
        setRefineStatus("Applying refinement…");
        const ok = await submitAIRequest({
          previewOnly: true,
          baseYaml: lastYaml,
          refinePrompt: instructions,
          button: refineBtn,
          spinnerMessage: "Applying refinement…",
        });
        if (ok) setRefineStatus("Preview updated. Review and refine again if needed.", "success");
        else setRefineStatus("Refinement failed. Please adjust your instructions and retry.", "error");
      });
    }

    if (publishBtn) {
      publishBtn.addEventListener("click", async () => {
        if (!lastYaml) {
          setRefineStatus("Generate a preview before publishing.", "error");
          return;
        }
        setRefineStatus("Validating & publishing…");
        const ok = await submitAIRequest({
          previewOnly: false,
          yamlOverride: lastYaml,
          button: publishBtn,
          spinnerMessage: "Validating & publishing…",
        });
        if (ok) setRefineStatus("", "info");
        else setRefineStatus("Publish failed. Check the logs and retry.", "error");
      });
    }

    if (discardBtn) {
      discardBtn.addEventListener("click", () => {
        if (!confirm("Are you sure you want to discard these guides and start over?")) {
          return;
        }
        lastYaml = "";
        hideRefineSection();
        showPreviewMessage("Preview cleared.");
        const yamlOut = el("yamlOutput");
        const buildOut = el("buildOutput");
        if (yamlOut) yamlOut.textContent = "";
        if (buildOut) buildOut.textContent = "";
        if (refineStatus) refineStatus.textContent = "";
        setStatus("Preview discarded. You can enter a new prompt.", "info");
      });
    }

    setRunButtonDisabled(false);
  });
})();
