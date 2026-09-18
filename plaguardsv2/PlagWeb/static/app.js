document.addEventListener("DOMContentLoaded", () => {
  // Analysis and PDF rendering are synchronous; show progress rather than
  // letting the page look frozen.
  const busy = document.getElementById("busyOverlay");
  const showBusy = (title, note) => {
    if (!busy) return;
    const t = document.getElementById("busyTitle");
    const n = document.getElementById("busyNote");
    if (t && title) t.textContent = title;
    if (n && note) n.textContent = note;
    busy.classList.add("open");
  };
  // A download replaces nothing on screen, so hide the overlay again once
  // the browser has had time to start the transfer.
  const flashBusy = (title, note) => {
    showBusy(title, note);
    setTimeout(() => busy && busy.classList.remove("open"), 2500);
  };

  const hideBusy = () => busy && busy.classList.remove("open");
  window.PlaguardsBusy = { show: showBusy, hide: hideBusy, flash: flashBusy };

  /* Everything here is synchronous server-side work, so any navigation can
     stall for a second or two. Rather than tagging each one, every form and
     every link that leaves the page raises the overlay; `data-busy` /
     `data-busy-note` override the wording and `data-no-busy` opts out. */
  const busyTextFor = (form, submitter) => {
    if (submitter && submitter.dataset.busy) return submitter.dataset.busy;
    if (form.dataset.busy) return form.dataset.busy;
    const label = (submitter && submitter.textContent || "").trim();
    return label ? `${label}…` : "Working…";
  };

  document.querySelectorAll("form").forEach((form) => {
    if (form.hasAttribute("data-no-busy")) return;
    form.addEventListener("submit", (e) => {
      const submitter = e.submitter;
      const input = form.querySelector("input[type=file]");
      const count = input && input.files ? input.files.length : 0;
      const note = (submitter && submitter.dataset.busyNote)
        || form.dataset.busyNote
        || "This runs locally, so it may take a moment.";

      if (form.classList.contains("analyze-form")) {
        // A combined batch report opens in its own tab, so this page stays
        // put and the overlay has to time out rather than wait for a reload.
        const opensTab = form.target === "_blank";
        const show = opensTab ? flashBusy : showBusy;
        show(count > 1 ? `Analyzing ${count} files…` : "Analyzing…",
             "Deobfuscating, extracting indicators and checking threat intel.");
        return;
      }
      // A download or a new tab leaves this page in place, so the overlay has
      // to time out rather than wait for a reload that never comes.
      const newTab = submitter && submitter.dataset.busyNewTab;
      if (newTab) form.target = "_blank";
      const stays = newTab || (submitter && submitter.dataset.busyDownload);
      const show = stays ? flashBusy : showBusy;
      show(busyTextFor(form, submitter), note);
      // Put it back, or the next submit would open a tab too.
      if (newTab) setTimeout(() => { form.target = ""; }, 0);
    });
  });

  document.querySelectorAll("a[href]").forEach((link) => {
    if (link.hasAttribute("data-no-busy")) return;
    const href = link.getAttribute("href");
    // In-page anchors, new tabs and JS hooks don't navigate this document.
    if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;
    if (link.hasAttribute("data-start-tour")) return;

    link.addEventListener("click", (e) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      const label = link.dataset.busyLink;
      // Downloads and new tabs never replace this page.
      if (label || link.target === "_blank" || link.hasAttribute("download")) {
        flashBusy(label || "Working…", link.dataset.busyNote || "Preparing your file.");
      } else {
        showBusy("Loading…", "Fetching the page.");
      }
    });
  });

  // Never leave the overlay up if the user comes back via the bfcache.
  window.addEventListener("pageshow", () => busy && busy.classList.remove("open"));

  const toggle = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
  }

  // Report options: keep the View/Download links in sync with the
  // "Include IOC findings" toggle.
  const iocToggle = document.getElementById("reportIocs");
  if (iocToggle) {
    const syncReportLinks = () => {
      ["viewReportBtn", "downloadReportBtn"].forEach((id) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.href = el.dataset.base + (iocToggle.checked ? "?redact=1" : "");
      });
    };
    iocToggle.addEventListener("change", syncReportLinks);
    syncReportLinks();
  }

  // Show the chosen filename next to the styled file button, and accept files
  // dropped anywhere on the drop zone the picker lives in.
  document.querySelectorAll(".file-picker input[type=file]").forEach((input) => {
    const picker = input.closest(".file-picker");
    const zone = picker.closest("[data-drop-zone]") || picker;
    const label = zone.querySelector(".file-name");

    const describe = () => {
      if (!label) return;
      const count = input.files.length;
      if (!count) label.textContent = "No file chosen";
      else if (count === 1) label.textContent = input.files[0].name;
      else label.textContent = `${count} files selected`;
    };
    input.addEventListener("change", describe);

    const hasFiles = (e) =>
      e.dataTransfer && Array.from(e.dataTransfer.types).includes("Files");

    /* The whole document is the drop target, not just the dashed box - there
       is only ever one file input on a page, so anywhere is unambiguous. The
       box still highlights so it is obvious where the files will land. */
    let depth = 0;
    document.addEventListener("dragenter", (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth += 1;
      zone.classList.add("drop-hover");
      document.body.classList.add("drop-active");
    });
    // Without preventDefault on dragover the browser just opens the file.
    document.addEventListener("dragover", (e) => {
      if (hasFiles(e)) e.preventDefault();
    });
    const clear = () => {
      depth = 0;
      zone.classList.remove("drop-hover");
      document.body.classList.remove("drop-active");
    };
    document.addEventListener("dragleave", (e) => {
      if (!hasFiles(e)) return;
      // Moving between elements fires dragleave; only clear on a real exit.
      depth -= 1;
      if (depth <= 0) clear();
    });
    document.addEventListener("dragend", clear);

    document.addEventListener("drop", (e) => {
      if (!hasFiles(e) || !e.dataTransfer.files.length) return;
      e.preventDefault();
      clear();
      input.files = e.dataTransfer.files;
      describe();
      zone.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  });

  /* The separate/combined choice is always on screen; the note under it just
     says whether the current selection will actually exercise it. */
  const batchNote = document.getElementById("batchNote");
  if (batchNote) {
    const fileInput = document.querySelector(".analyze-form input[type=file]");
    const syncBatchNote = () => {
      const files = fileInput && fileInput.files ? Array.from(fileInput.files) : [];
      const zipped = files.some((f) => /\.zip$/i.test(f.name));
      const batch = files.length > 1 || zipped;
      batchNote.classList.toggle("is-active", batch);
      if (files.length > 1) {
        batchNote.textContent = `${files.length} files selected — this is what you'll get back.`;
      } else if (zipped) {
        batchNote.textContent = "An archive is selected — this is what you'll get back.";
      } else {
        batchNote.textContent = "Choose files above and this decides what you get back.";
      }
    };
    if (fileInput) fileInput.addEventListener("change", syncBatchNote);
    // Files can also arrive by drop, which sets .files directly.
    document.addEventListener("drop", () => setTimeout(syncBatchNote, 0));
    syncBatchNote();

    /* Choosing "Combined report" produces a document rather than a page, so
       it opens in its own tab and leaves this form where it is. */
    const form = document.querySelector(".analyze-form");
    const syncTarget = () => {
      const combined = document.querySelector("input[name=batch_report]:checked");
      form.target = combined && combined.value === "combined" ? "_blank" : "";
    };
    document.querySelectorAll("input[name=batch_report]").forEach(
      (radio) => radio.addEventListener("change", syncTarget));
    syncTarget();
  }

  // Custom up/down buttons drawn over a number input, standing in for its
  // hidden native spinner - stepUp/stepDown already respect min/max/step,
  // so there's no arithmetic to duplicate here.
  document.querySelectorAll(".number-field").forEach((field) => {
    const input = field.querySelector("input[type=number]");
    field.querySelectorAll(".number-step").forEach((btn) => {
      btn.addEventListener("click", () => {
        try {
          btn.dataset.step === "up" ? input.stepUp() : input.stepDown();
        } catch {
          // Value doesn't currently line up with `step`; leave it alone
          // rather than throwing the click away with no feedback.
        }
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
  });

  // Expand / collapse every finding card at once.
  document.querySelectorAll("[data-expand-all]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const open = btn.dataset.expandAll === "1";
      document.querySelectorAll("details.finding-card").forEach((d) => {
        d.open = open;
      });
    });
  });

  // Apply one verdict to every finding in a single request, then reflect it
  // in each card without a page reload.
  document.querySelectorAll("[data-bulk-status]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const status = btn.dataset.bulkStatus;
      const buttons = document.querySelectorAll("[data-bulk-status]");
      buttons.forEach((b) => (b.disabled = true));
      try {
        const resp = await fetch(`/analysis/${window.ANALYSIS_ID}/triage-all`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status }),
        });
        if (!resp.ok) throw new Error("request failed");
        const data = await resp.json();
        document.querySelectorAll(".finding-card").forEach((card) => {
          const statusEl = card.querySelector(".triage-status");
          if (!statusEl) return;
          statusEl.textContent = data.status.replace("_", " ");
          statusEl.dataset.current = data.status;
          card.querySelectorAll(".tbtn[data-status]").forEach((b) =>
            b.classList.toggle("active", b.dataset.status === data.status)
          );
        });
      } catch (err) {
        alert("Could not update all findings: " + err.message);
      } finally {
        buttons.forEach((b) => (b.disabled = false));
      }
    });
  });

  document.querySelectorAll(".finding-card").forEach((card) => {
    const findingId = card.dataset.findingId;
    const statusEl = card.querySelector(".triage-status");
    const buttons = card.querySelectorAll(".tbtn");

    const applyActiveState = (status) => {
      buttons.forEach((b) => b.classList.toggle("active", b.dataset.status === status));
    };
    applyActiveState(statusEl.dataset.current);

    buttons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const status = btn.dataset.status;
        btn.disabled = true;
        try {
          const resp = await fetch(`/analysis/${window.ANALYSIS_ID}/finding/${findingId}/triage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status }),
          });
          if (!resp.ok) throw new Error("request failed");
          const data = await resp.json();
          statusEl.textContent = data.status.replace("_", " ");
          statusEl.dataset.current = data.status;
          applyActiveState(data.status);
        } catch (err) {
          alert("Could not update triage status: " + err.message);
        } finally {
          btn.disabled = false;
        }
      });
    });
  });
});
