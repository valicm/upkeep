// The dashboard works without this file. It adds four comforts: a theme switch that remembers,
// a filter box, exact times in the reader's own time zone, and a quiet refresh.
(function () {
  "use strict";

  var KEY = "upkeep-theme";
  var REFRESH_MS = 60000;
  var root = document.documentElement;

  // Theme: auto follows the browser. The first click goes to the theme the reader does not see
  // right now, so that it always changes something.
  var themeButton = document.getElementById("theme");

  function currentTheme() {
    return root.getAttribute("data-theme") || "auto";
  }

  function systemTheme() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function setTheme(theme) {
    if (theme === "auto") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", theme);
    }
    try {
      if (theme === "auto") {
        localStorage.removeItem(KEY);
      } else {
        localStorage.setItem(KEY, theme);
      }
    } catch (e) {
      // Without storage the choice lasts for this page only.
    }
    themeButton.textContent = "Theme: " + theme;
  }

  if (themeButton) {
    themeButton.hidden = false;
    themeButton.textContent = "Theme: " + currentTheme();
    themeButton.addEventListener("click", function () {
      var other = systemTheme() === "dark" ? "light" : "dark";
      var now = currentTheme();
      setTheme(now === "auto" ? other : now === other ? systemTheme() : "auto");
    });
  }

  // Times: the server prints them in its own zone; the tooltip gets the reader's.
  function localTimes(scope) {
    scope.querySelectorAll("time[datetime]").forEach(function (el) {
      var d = new Date(el.getAttribute("datetime"));
      if (!isNaN(d.getTime())) {
        el.title = d.toLocaleString();
      }
    });
    var stamp = document.querySelector("#stamp time");
    if (stamp) {
      var s = new Date(stamp.getAttribute("datetime"));
      if (!isNaN(s.getTime())) {
        stamp.textContent = s.toLocaleTimeString();
      }
    }
  }

  // Filter: hides rows that do not contain the typed text. A group (a system on the updates
  // page, a severity on the overview) stays while one of its rows does, and typing a group's
  // name shows all of it.
  var filter = document.getElementById("filter");
  var filterCount = document.getElementById("filter-count");

  function applyFilter() {
    if (!filter) {
      return;
    }
    var main = document.getElementById("main");
    var q = filter.value.trim().toLowerCase();
    var rows = main.querySelectorAll("[data-row]");
    var shown = 0;

    rows.forEach(function (row) {
      var group = row.closest("[data-group]");
      var hit = !q || row.textContent.toLowerCase().indexOf(q) >= 0 ||
        (group && group.getAttribute("data-group").toLowerCase().indexOf(q) >= 0);
      row.hidden = !hit;
      if (hit) {
        shown++;
      }
    });

    main.querySelectorAll("[data-group]").forEach(function (group) {
      group.hidden = !!q && group.getAttribute("data-group").toLowerCase().indexOf(q) < 0 &&
        !group.querySelector("[data-row]:not([hidden])");
    });

    // A match inside a closed list would be invisible: open it for as long as the filter
    // is in use, and close it again afterwards.
    main.querySelectorAll("details").forEach(function (d) {
      var hasRows = d.querySelector("[data-row]");
      if (!hasRows) {
        return;
      }
      if (q && !d.open && d.querySelector("[data-row]:not([hidden])")) {
        d.open = true;
        d.setAttribute("data-opened-by-filter", "");
      } else if (!q && d.hasAttribute("data-opened-by-filter")) {
        d.open = false;
        d.removeAttribute("data-opened-by-filter");
      }
    });

    if (filterCount) {
      filterCount.textContent = q ? shown + " of " + rows.length + " rows" : "";
    }
  }

  if (filter && document.querySelector("#main [data-row]")) {
    filter.hidden = false;
    filter.addEventListener("input", applyFilter);
    filter.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && filter.value) {
        filter.value = "";
        applyFilter();
      }
    });
    document.addEventListener("keydown", function (e) {
      var el = document.activeElement;
      var typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
      if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        filter.focus();
      }
    });
  }

  // Refresh: fetch the same page and swap its content in, so that a list someone opened stays
  // open and nothing jumps. It waits while the tab is hidden or text is selected.
  function refresh() {
    if (document.visibilityState !== "visible") {
      return;
    }
    var selection = window.getSelection ? window.getSelection() : null;
    if (selection && !selection.isCollapsed) {
      return;
    }
    fetch(window.location.href, { credentials: "same-origin", cache: "no-store" })
      .then(function (res) {
        if (!res.ok) {
          throw new Error("status " + res.status);
        }
        return res.text();
      })
      .then(function (html) {
        var fresh = new DOMParser().parseFromString(html, "text/html");
        var freshMain = fresh.getElementById("main");
        var freshStamp = fresh.getElementById("stamp");
        var main = document.getElementById("main");
        var stamp = document.getElementById("stamp");
        if (!freshMain || !main) {
          return;
        }
        main.querySelectorAll("details[id]").forEach(function (d) {
          var twin = fresh.getElementById(d.id);
          if (twin && twin.tagName === "DETAILS") {
            twin.open = d.open;
            if (d.hasAttribute("data-opened-by-filter")) {
              twin.setAttribute("data-opened-by-filter", "");
            }
          }
        });
        // Whoever reads the raw report keeps their place in it.
        var raw = document.getElementById("raw-json");
        var rawTop = raw ? raw.scrollTop : 0;
        var rawLeft = raw ? raw.scrollLeft : 0;
        main.replaceWith(document.importNode(freshMain, true));
        raw = document.getElementById("raw-json");
        if (raw) {
          raw.scrollTop = rawTop;
          raw.scrollLeft = rawLeft;
        }
        if (stamp && freshStamp) {
          stamp.replaceWith(document.importNode(freshStamp, true));
        }
        localTimes(document);
        applyFilter();
      })
      .catch(function () {
        var stamp = document.getElementById("stamp");
        if (stamp && !stamp.classList.contains("stale")) {
          stamp.classList.add("stale");
          stamp.appendChild(document.createTextNode(", the refresh failed"));
        }
      });
  }

  localTimes(document);
  // Only a page that shows state is kept fresh: an error page would only repeat its error.
  var live = document.getElementById("main");
  if (live && live.hasAttribute("data-live")) {
    window.setInterval(refresh, REFRESH_MS);
    document.addEventListener("visibilitychange", function () {
      // Someone coming back to the tab wants the present, not the page from an hour ago.
      var stamp = document.querySelector("#stamp time");
      var age = stamp ? Date.now() - new Date(stamp.getAttribute("datetime")).getTime() : 0;
      if (document.visibilityState === "visible" && age > REFRESH_MS) {
        refresh();
      }
    });
  }
})();
