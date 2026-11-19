// Runs before the page is drawn, so a remembered theme never flashes the other one first.
(function () {
  try {
    var t = localStorage.getItem("upkeep-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) {
    // No storage (private window, blocked): the browser's preference decides.
  }
})();
