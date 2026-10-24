/* Pocolo, a guided product tour: spotlights one feature at a time. Steps are
 * declared per page, and a step whose target is absent is skipped. */
(function () {
  "use strict";

  const SEEN_KEY = "plaguardsv2.tourSeen";

  /* Grouped per feature so the Tutorial can tour one area; "everything" chains
     them, navigating to each step's `page` and resuming there. */
  const TOURS = {
    navigation: {
      label: "Getting around",
      steps: [
        {
          target: "#sidebar .profile-img", page: "/",
          title: "Hi, I'm Pocolo",
          body: "I'll walk you through PlaguardsV2 one feature at a time. Leave whenever you like with Skip.",
          placement: "right",
        },
        {
          target: "#navmenu", page: "/",
          title: "The main areas",
          body: "Analyze runs a script, History keeps your recent ones, Tutorial explains every feature, and Settings holds API keys and preferences.",
          placement: "right",
        },
      ],
    },
    analysis: {
      label: "Running an analysis",
      steps: [
        {
          target: "textarea[name='script_text']", page: "/",
          title: "Paste a script",
          body: "Drop an obfuscated PowerShell script in here, or VBS, JScript, batch, a raw log line. Nothing is ever executed; it is all static text analysis.",
          placement: "right",
        },
        {
          target: ".drop-zone", page: "/",
          title: "…or bring files in",
          body: "Click Choose files, or drag them from Explorer. Anywhere on the page works, not just this box. .ps1 .txt .vbs .js .bat .cmd .log, or a .zip, analyzed one by one.",
          placement: "top",
        },
        {
          target: "input[name='skip_intel']", page: "/",
          title: "Working offline?",
          body: "Tick this to skip threat-intel lookups. Deobfuscation and IOC extraction still run, and never leave this machine.",
          placement: "top",
        },
        {
          target: "#batchChoice", page: "/",
          title: "One report or many?",
          body: "Submitting several files? Separate reports gives one PDF each and lands on History with the batch selected; Combined gives you a single document covering all of them.",
          placement: "top",
        },
        {
          target: ".analyze-form button[type=submit]", page: "/",
          title: "Run it",
          body: "Analyze takes you to the result page: deobfuscated script on the left, findings on the right. Several files at once land in History instead.",
          placement: "top",
        },
      ],
    },
    lookup: {
      label: "Quick IOC Lookup",
      steps: [
        {
          target: ".lookup-form", page: "/",
          title: "Check a single indicator",
          body: "Already have one IP, domain, URL, hash or malware family? Check it straight against your configured providers without running a full analysis. Nothing is stored in History.",
          placement: "left",
        },
        {
          target: ".lookup-type", page: "/",
          title: "Pick a type, or don't",
          body: "Left on auto, the value's shape decides. Choose one to force it, and to reach Malware signature / family, which has no shape to detect: AgentTesla, Formbook, and so on.",
          placement: "left",
        },
      ],
    },
    findings: {
      label: "Reading findings",
      steps: [
        {
          target: ".pass-log-details", page: "latest",
          title: "What was applied",
          body: "The transform log lists every pass that changed something, in the order it ran. Anything not listed here was left untouched.",
          placement: "right",
        },
        {
          target: ".resolved-table", page: "latest",
          title: "Resolved variables",
          body: "Values rebuilt by folding literals through concatenation, Base64 and string operations. This is where the real C2 address usually surfaces.",
          placement: "right",
        },
        {
          target: "#encodedRuns", page: "latest",
          title: "Encoded runs",
          body: "Every encoded string left in the script, with the CyberChef recipe that opened it, such as From Hex > From Base64 > Gunzip. With the offline CyberChef installed, its button opens that recipe on the run.",
          placement: "right",
        },
        {
          target: ".original-details", page: "latest",
          title: "The original input",
          body: "Open this to see exactly what you submitted, untouched, next to the cleaned-up version.",
          placement: "right",
        },
        {
          target: ".finding-card", page: "latest",
          title: "Open a finding",
          body: "Each card expands to show its surrounding context, its MITRE ATT&CK mapping, and the threat-intel verdict. Click any provider row to open its own page for the indicator.",
          placement: "left",
        },
        {
          target: "[data-expand-all]", page: "latest",
          title: "All at once",
          body: "Expand all / Collapse all when you want to read straight through the list rather than clicking card by card.",
          placement: "bottom",
        },
        {
          target: ".bulk-triage", page: "latest",
          title: "Triage in bulk",
          body: "Mark every finding at once, then refine the individual ones that deserve a closer look.",
          placement: "bottom",
        },
        {
          target: ".triage-buttons", page: "latest",
          title: "Record your verdict",
          body: "Confirm Threat, False Positive or Unknown. Severity describes the technique observed. Your call is what the report treats as authoritative.",
          placement: "left",
        },
      ],
    },
    threatintel: {
      label: "Threat intelligence",
      steps: [
        {
          target: ".intel-summary", page: "latest",
          title: "One headline, not five",
          body: "Every provider that supports this indicator type is asked, and the worst verdict any of them returned becomes the headline. The count next to it says how many actually answered.",
          placement: "left",
        },
        {
          target: ".intel-block", page: "latest",
          title: "Open the breakdown",
          body: "Each provider's own answer, with the detail it gave: detections, open ports, pulse names. Click any row to open that provider's page for this indicator in a new tab.",
          placement: "left",
        },
      ],
    },
    geolocation: {
      label: "Where the addresses are",
      steps: [
        {
          target: "#geoSection", page: "/settings",
          title: "Point it at a database",
          body: "Give it MaxMind's GeoLite2 City, Country or ASN: a .mmdb, a folder, or the .tar.gz exactly as downloaded. With a local database the address never leaves this machine.",
          placement: "top",
        },
        {
          target: ".result-actions", page: "latest",
          title: "It travels with the findings",
          body: "Country, region, coordinates, the radius those coordinates are good to, ASN and reverse DNS land in the report and in every Excel and CSV export.",
          placement: "bottom",
        },
      ],
    },
    reports: {
      label: "Reports",
      steps: [
        {
          target: "#reportIocs", page: "latest",
          title: "Redact before sharing",
          body: "Tick this and indicator values print black-on-black in the PDF: present in the document, but not readable at a glance.",
          placement: "bottom",
        },
        {
          target: "#viewReportBtn", page: "latest",
          title: "View or download",
          body: "Cover, a clickable contents with page numbers, and a formal disclaimer first, then page 1: the summary, findings table, per-finding detail, transforms, and both scripts.",
          placement: "bottom",
        },
      ],
    },
    history: {
      label: "History",
      steps: [
        {
          target: ".history-table", page: "/history",
          title: "Recent analyses",
          body: "Newest first, with the finding count and how many were high severity. View reopens one with its triage verdicts intact.",
          placement: "top",
        },
        {
          target: ".bulk-bar", page: "/history",
          title: "Bulk actions",
          body: "Select rows to export separate PDFs as a zip, build one Combined report covering all of them, or delete them together.",
          placement: "bottom",
        },
      ],
    },
    credits: {
      label: "Credits",
      steps: [
        {
          target: ".sidebar-links", page: "/",
          title: "Where this came from",
          body: "The authors' GitHub profiles, plus Plaguards v1, the project PlaguardsV2 is built on. Each opens in a new tab.",
          placement: "right",
        },
      ],
    },
    settings: {
      label: "Settings",
      steps: [
        {
          target: ".settings-form", page: "/settings",
          title: "Threat-intel API keys",
          body: "Add keys for any of the providers listed. Green means configured, red means that provider is skipped. Leaving a field blank keeps the stored key; Remove forgets one.",
          placement: "right",
        },
        {
          target: "#geoSection", page: "/settings",
          title: "Geolocation databases",
          body: "Point these at MaxMind's GeoLite2 City, Country and ASN files: a .mmdb, a folder, or the .tar.gz as downloaded. Whichever you fill in are merged into one record per address, and nothing leaves this machine.",
          placement: "top",
        },
        {
          target: "#cyberchefSection", page: "/settings",
          title: "CyberChef, offline",
          body: "Whether the local copy of CyberChef is installed. It runs from this server and cannot send data anywhere else; if it's missing, this section shows the one command that installs it.",
          placement: "top",
        },
        {
          target: "#generalSection", page: "/settings",
          title: "General preferences",
          body: "How many analyses to keep, the name printed on reports, and the UTC offset used for every timestamp.",
          placement: "top",
        },
        {
          target: "#dangerSection", page: "/settings",
          title: "Danger zone",
          body: "Clears every stored analysis, finding and triage decision. Your API keys and general settings survive it.",
          placement: "top",
        },
      ],
    },
  };

  const ORDER = ["navigation", "analysis", "lookup", "findings", "threatintel",
                 "geolocation", "reports", "history", "settings", "credits"];

  let steps = [];
  let index = 0;
  let chapterKey = null;
  let currentLabel = null;
  let nodes = null;

  function visible(el) {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.height > 0) return true;
    // Present but inside something collapsed - go() opens it on arrival.
    return !!el.closest("details:not([open])");
  }

  function build() {
    const overlay = document.createElement("div");
    overlay.className = "tour-overlay";
    overlay.innerHTML = `
      <div class="tour-hole"></div>
      <div class="tour-pop" role="dialog" aria-live="polite">
        <div class="tour-pop-head">
          <img class="tour-avatar" src="${window.POCOLO_SRC || ""}" alt="Pocolo" />
          <div>
            <div class="tour-title"></div>
            <div class="tour-count"></div>
            <div class="tour-progress"><span class="tour-progress-fill"></span></div>
          </div>
        </div>
        <p class="tour-body"></p>
        <div class="tour-actions">
          <button type="button" class="tour-skip">Skip</button>
          <span class="tour-spacer"></span>
          <button type="button" class="tour-prev">Back</button>
          <button type="button" class="tour-next">Next</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    nodes = {
      overlay,
      hole: overlay.querySelector(".tour-hole"),
      pop: overlay.querySelector(".tour-pop"),
      title: overlay.querySelector(".tour-title"),
      count: overlay.querySelector(".tour-count"),
      progress: overlay.querySelector(".tour-progress-fill"),
      body: overlay.querySelector(".tour-body"),
      prev: overlay.querySelector(".tour-prev"),
      next: overlay.querySelector(".tour-next"),
      skip: overlay.querySelector(".tour-skip"),
    };

    nodes.next.addEventListener("click", () => go(index + 1));
    nodes.prev.addEventListener("click", () => go(index - 1));
    nodes.skip.addEventListener("click", () => stop());
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) stop();
    });
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
  }

  function onKey(e) {
    if (!nodes || !nodes.overlay.classList.contains("open")) return;
    if (e.key === "Escape") stop();
    if (e.key === "ArrowRight") go(index + 1);
    if (e.key === "ArrowLeft") go(index - 1);
  }

  function reposition() {
    if (!nodes || !nodes.overlay.classList.contains("open")) return;
    const step = steps[index];
    const el = document.querySelector(step.target);
    if (!el) return;

    const r = el.getBoundingClientRect();
    const pad = 8;
    Object.assign(nodes.hole.style, {
      top: `${r.top - pad}px`,
      left: `${r.left - pad}px`,
      width: `${r.width + pad * 2}px`,
      height: `${r.height + pad * 2}px`,
    });

    const pop = nodes.pop;
    const pw = pop.offsetWidth || 320;
    const ph = pop.offsetHeight || 160;
    const gap = 16;
    let top;
    let left;

    switch (step.placement) {
      case "right":
        top = r.top + r.height / 2 - ph / 2;
        left = r.right + gap;
        break;
      case "left":
        top = r.top + r.height / 2 - ph / 2;
        left = r.left - pw - gap;
        break;
      case "top":
        top = r.top - ph - gap;
        left = r.left + r.width / 2 - pw / 2;
        break;
      default:
        top = r.bottom + gap;
        left = r.left + r.width / 2 - pw / 2;
    }

    // Keep the bubble on screen.
    left = Math.max(12, Math.min(left, window.innerWidth - pw - 12));
    top = Math.max(12, Math.min(top, window.innerHeight - ph - 12));
    pop.style.top = `${top}px`;
    pop.style.left = `${left}px`;
  }

  function go(next) {
    if (next < 0) return;
    if (next >= steps.length) {
      if (chapterKey) {
        markChapterDone(chapterKey);
        stop({ keepProgress: true });
        return start("everything");
      }
      return stop();
    }
    index = next;
    const step = steps[index];
    const el = document.querySelector(step.target);
    if (!el) return go(next > index ? next + 1 : next - 1);

    // Ancestors and descendants, not just the nearest: a finding card is a
    // <details> whose intel panel is another. Left open after the tour.
    let opened = false;
    for (let node = el.closest("details"); node;
         node = node.parentElement && node.parentElement.closest("details")) {
      if (!node.open) {
        node.open = true;
        opened = true;
      }
    }
    el.querySelectorAll("details:not([open])").forEach((inner) => {
      inner.open = true;
      opened = true;
    });
    if (opened) setTimeout(reposition, 60);

    nodes.title.textContent = step.title;
    nodes.body.textContent = step.body;
    nodes.count.textContent = currentLabel
      ? `${currentLabel} · step ${index + 1} of ${steps.length}`
      : `Step ${index + 1} of ${steps.length}`;
    nodes.progress.style.width = `${((index + 1) / steps.length) * 100}%`;
    nodes.prev.disabled = index === 0;
    nodes.next.textContent = index === steps.length - 1 ? "Finish" : "Next";

    el.scrollIntoView({ behavior: "smooth", block: "center" });
    setTimeout(reposition, 220);
  }

  function collect(name) {
    if (name === "everything") {
      return ORDER.reduce((all, key) => all.concat(TOURS[key].steps), []);
    }
    return (TOURS[name] || TOURS.navigation).steps;
  }

  /* A tour may reference a page we aren't on. Send the browser there with
     the tour name in the query string and let it resume on load. */
  function relocate(name, wanted, quiet) {
    let href = wanted;
    if (wanted === "latest") {
      if (!window.LATEST_ANALYSIS_ID) {
        if (!quiet) alert("Run an analysis first. This part of the tour needs some results to point at.");
        return false;
      }
      href = `/analysis/${window.LATEST_ANALYSIS_ID}`;
    }
    // Already here and the targets still aren't on the page - reloading would
    // only bounce us round in circles, so let the caller move on instead.
    if (href === window.location.pathname) return false;
    window.location.href = `${href}?tour=${encodeURIComponent(name)}`;
    return true;
  }

  /* "Tour everything" spans pages: outstanding chapters are remembered, and
     the tour moves on when this page's steps run out. */
  function remaining(name) {
    if (name !== "everything") return [];
    const done = sessionStorage.getItem("plaguardsv2.tourDone");
    const seen = done ? JSON.parse(done) : [];
    return ORDER.filter((key) => !seen.includes(key));
  }

  function markChapterDone(key) {
    const done = sessionStorage.getItem("plaguardsv2.tourDone");
    const seen = done ? JSON.parse(done) : [];
    if (!seen.includes(key)) seen.push(key);
    sessionStorage.setItem("plaguardsv2.tourDone", JSON.stringify(seen));
  }

  function start(name) {
    const wanted = name || "everything";

    if (wanted === "everything") {
      // Walk the chapters in order, hopping pages as needed.
      for (const key of remaining("everything")) {
        const chapter = TOURS[key].steps;
        const here = chapter.filter((s) => visible(document.querySelector(s.target)));
        if (here.length) {
          chapterKey = key;
          currentLabel = TOURS[key].label;
          steps = here;
          if (!nodes) build();
          nodes.overlay.classList.add("open");
          document.body.classList.add("tour-active");
          go(0);
          return;
        }
        const target = chapter.find((s) => s.page);
        if (target && relocate("everything", target.page, true)) return;
        markChapterDone(key);
      }
      sessionStorage.removeItem("plaguardsv2.tourDone");
      alert("That's the whole tour. You're all caught up.");
      return;
    }

    chapterKey = null;
    currentLabel = (TOURS[wanted] || {}).label || null;
    const all = collect(wanted);
    steps = all.filter((s) => visible(document.querySelector(s.target)));

    if (!steps.length) {
      const target = all.find((s) => s.page);
      if (target && relocate(wanted, target.page)) return;
      alert("Nothing to show here yet.");
      return;
    }

    if (!nodes) build();
    nodes.overlay.classList.add("open");
    document.body.classList.add("tour-active");
    go(0);
  }

  function stop(opts) {
    if (!nodes) return;
    nodes.overlay.classList.remove("open");
    document.body.classList.remove("tour-active");
    // Skipping abandons the whole tour, so forget how far we got.
    if (!(opts && opts.keepProgress)) {
      chapterKey = null;
      sessionStorage.removeItem("plaguardsv2.tourDone");
    }
    try {
      localStorage.setItem(SEEN_KEY, "1");
    } catch (e) {
      /* private mode - just don't remember */
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-start-tour]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        start(btn.dataset.startTour || "everything");
      });
    });

    const params = new URLSearchParams(window.location.search);
    const requested = params.get("tour");
    if (requested) {
      const name = requested === "1" ? "everything" : requested;
      setTimeout(() => start(name), 350);
    }
  });

  window.PlaguardsTour = { start, stop };
})();
