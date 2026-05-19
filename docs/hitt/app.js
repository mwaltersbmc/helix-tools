(function () {
  "use strict";

  var statusEl = document.getElementById("status");
  var rootEl = document.getElementById("use-cases");

  function num(x, def) {
    if (typeof x === "number" && !isNaN(x)) return x;
    if (typeof x === "string" && x.trim() !== "" && !isNaN(Number(x))) return Number(x);
    return def;
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try {
        if (document.execCommand("copy")) resolve();
        else reject(new Error("execCommand copy returned false"));
      } catch (err) {
        reject(err);
      }
      document.body.removeChild(ta);
    });
  }

  var CLIPBOARD_SVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  var CHECK_SVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>';

  function appendCommandBlock(panel, line) {
    var wrap = document.createElement("div");
    wrap.className = "command-block";
    var pre = document.createElement("pre");
    pre.textContent = line;
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-icon-btn";
    btn.setAttribute("aria-label", "Copy command");
    btn.setAttribute("title", "Copy command");
    btn.innerHTML = CLIPBOARD_SVG;
    btn.addEventListener("click", function (ev) {
      ev.preventDefault();
      ev.stopPropagation();
      copyText(line)
        .then(function () {
          btn.innerHTML = CHECK_SVG;
          btn.setAttribute("aria-label", "Copied");
          btn.setAttribute("title", "Copied");
          setTimeout(function () {
            btn.innerHTML = CLIPBOARD_SVG;
            btn.setAttribute("aria-label", "Copy command");
            btn.setAttribute("title", "Copy command");
          }, 1500);
        })
        .catch(function () {
          btn.setAttribute("title", "Copy failed");
          setTimeout(function () {
            btn.setAttribute("title", "Copy command");
          }, 1500);
        });
    });
    wrap.appendChild(pre);
    wrap.appendChild(btn);
    panel.appendChild(wrap);
  }

  function renderUseCase(uc) {
    var det = document.createElement("details");
    var sum = document.createElement("summary");
    sum.textContent = uc.title || uc.id || "Untitled";
    det.appendChild(sum);

    var panel = document.createElement("div");
    panel.className = "panel";

    if (uc.commands && uc.commands.length) {
      var hCmd = document.createElement("h2");
      hCmd.textContent = "Commands";
      panel.appendChild(hCmd);
      uc.commands.forEach(function (line) {
        appendCommandBlock(panel, line);
      });
    }

    if (uc.notes && uc.notes.length) {
      var hN = document.createElement("h2");
      hN.textContent = "Notes";
      panel.appendChild(hN);
      var ul = document.createElement("ul");
      ul.className = "notes";
      uc.notes.forEach(function (n) {
        var li = document.createElement("li");
        li.textContent = n;
        ul.appendChild(li);
      });
      panel.appendChild(ul);
    }

    if (uc.seeAlso) {
      var hL = document.createElement("h2");
      hL.textContent = "Documentation";
      panel.appendChild(hL);
      var p = document.createElement("p");
      var a = document.createElement("a");
      a.className = "doc";
      a.href = uc.seeAlso;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = uc.seeAlso;
      p.appendChild(a);
      panel.appendChild(p);
    }

    det.appendChild(panel);
    return det;
  }

  function render(data) {
    var rawTopics = data.topics && data.topics.length ? data.topics.slice() : [];
    var cases = (data.useCases || []).slice();

    rawTopics.sort(function (a, b) {
      var oa = num(a.order, 9999);
      var ob = num(b.order, 9999);
      if (oa !== ob) return oa - ob;
      return String(a.id || "").localeCompare(String(b.id || ""));
    });

    var topicOrder = [];
    var topicMeta = {};
    rawTopics.forEach(function (t) {
      if (!t || !t.id) return;
      topicOrder.push(t.id);
      topicMeta[t.id] = t.title || t.id;
    });

    var byTopic = {};
    topicOrder.forEach(function (id) {
      byTopic[id] = [];
    });

    var orphan = [];

    cases.forEach(function (uc) {
      var tid = uc.topicId;
      if (tid && Object.prototype.hasOwnProperty.call(byTopic, tid)) {
        byTopic[tid].push(uc);
      } else {
        orphan.push(uc);
      }
    });

    topicOrder.forEach(function (tid) {
      byTopic[tid].sort(function (a, b) {
        var oa = num(a.order, 0);
        var ob = num(b.order, 0);
        if (oa !== ob) return oa - ob;
        return String(a.id || "").localeCompare(String(b.id || ""));
      });
    });

    orphan.sort(function (a, b) {
      var oa = num(a.order, 0);
      var ob = num(b.order, 0);
      if (oa !== ob) return oa - ob;
      return String(a.id || "").localeCompare(String(b.id || ""));
    });

    var frag = document.createDocumentFragment();

    topicOrder.forEach(function (tid) {
      var list = byTopic[tid];
      if (!list.length) return;

      var sec = document.createElement("section");
      sec.className = "topic-section";
      var h = document.createElement("h2");
      h.className = "topic-title";
      h.textContent = topicMeta[tid] || tid;
      sec.appendChild(h);

      list.forEach(function (uc) {
        sec.appendChild(renderUseCase(uc));
      });
      frag.appendChild(sec);
    });

    if (orphan.length) {
      var secO = document.createElement("section");
      secO.className = "topic-section";
      var hO = document.createElement("h2");
      hO.className = "topic-title";
      hO.textContent = "Unassigned (set topicId on these use cases)";
      secO.appendChild(hO);
      orphan.forEach(function (uc) {
        secO.appendChild(renderUseCase(uc));
      });
      frag.appendChild(secO);
    }

    rootEl.innerHTML = "";
    rootEl.appendChild(frag);
  }

  function fail(msg) {
    statusEl.hidden = false;
    statusEl.textContent = msg;
  }

  document.getElementById("expand-all-btn").addEventListener("click", function () {
    rootEl.querySelectorAll("details").forEach(function (d) {
      d.open = true;
    });
  });
  document.getElementById("collapse-all-btn").addEventListener("click", function () {
    rootEl.querySelectorAll("details").forEach(function (d) {
      d.open = false;
    });
  });

  function loadData() {
    if (typeof window.HITT_USE_CASES !== "undefined" && window.HITT_USE_CASES !== null) {
      return Promise.resolve(window.HITT_USE_CASES);
    }
    var embed = document.getElementById("hitt-use-cases-embed");
    if (embed && embed.textContent) {
      try {
        return Promise.resolve(JSON.parse(embed.textContent));
      } catch (err) {
        return Promise.reject(err);
      }
    }
    var jsonUrl = new URL("use-cases.json", document.baseURI).href;
    return fetch(jsonUrl, { cache: "no-cache" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status + " loading use-cases.json");
      return r.json();
    });
  }

  loadData()
    .then(function (data) {
      render(data);
      statusEl.textContent = "";
      statusEl.hidden = true;
    })
    .catch(function (e) {
      fail(
        "Could not load use cases (" +
          e.message +
          "). For file:// open, keep use-cases-data.js next to index.html (run update-bundled-data.ps1 after editing JSON), or use a local web server."
      );
      console.error(e);
    });
})();
