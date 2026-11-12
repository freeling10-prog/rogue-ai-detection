/* Clipboard intake for the pricing ladder. No network. */
(function () {
  "use strict";

  var LABEL = "Copy alec@room23.net + Request Template";
  var COPIED = "Copied to clipboard!";
  var ADDRESS = "alec@room23.net";
  var RESTORE_AFTER = 2500;

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "readonly");
    ta.setAttribute("aria-hidden", "true");
    ta.style.position = "fixed";
    ta.style.top = "0";
    ta.style.left = "0";
    ta.style.width = "1px";
    ta.style.height = "1px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  function writeText(text) {
    var clip = navigator.clipboard;
    if (clip && typeof clip.writeText === "function") {
      return clip.writeText(text).catch(function () {
        if (fallbackCopy(text)) return;
        throw new Error("copy failed");
      });
    }
    if (fallbackCopy(text)) return Promise.resolve();
    return Promise.reject(new Error("copy failed"));
  }

  function payloadFor(tier) {
    return ADDRESS + "\n\n" + tier.body;
  }

  function flash(btn) {
    var pending = btn._copyTimer;
    if (pending) window.clearTimeout(pending);
    btn.textContent = COPIED;
    btn._copyTimer = window.setTimeout(function () {
      btn.textContent = LABEL;
      btn._copyTimer = 0;
    }, RESTORE_AFTER);
  }

  var dataNode = document.getElementById("intake-data");
  if (!dataNode) return;
  var intake = JSON.parse(dataNode.textContent);

  Array.prototype.forEach.call(document.querySelectorAll("button[data-tier]"), function (btn) {
    btn.addEventListener("click", function () {
      var tier = intake[btn.getAttribute("data-tier")];
      if (!tier) return;
      writeText(payloadFor(tier)).then(function () { flash(btn); }, function () {});
    });
  });
})();
