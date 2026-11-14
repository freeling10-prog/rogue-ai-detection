/* Clipboard intake for the pricing ladder. No network. */
(function () {
  "use strict";

  var LABEL = "Copy alec@room23.net + Request Template";
  var COPIED = "Copied to clipboard!";
  var ADDRESS = "alec@room23.net";
  var FAILED = "Copy failed \u2014 copy " + ADDRESS + " by hand";
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

  function relabel(btn, text, holdFor) {
    var pending = btn._copyTimer;
    if (pending) window.clearTimeout(pending);
    btn.textContent = text;
    btn._copyTimer = window.setTimeout(function () {
      btn.textContent = LABEL;
      btn._copyTimer = 0;
    }, holdFor);
  }

  function flash(btn) {
    hideFallback(btn);
    relabel(btn, COPIED, RESTORE_AFTER);
  }

  function fallbackNote(btn) {
    return btn.parentNode ? btn.parentNode.querySelector(".copy-fallback") : null;
  }

  function hideFallback(btn) {
    var note = fallbackNote(btn);
    if (note) note.hidden = true;
  }

  /* Both navigator.clipboard.writeText and execCommand("copy") failed:
     say so where the person is looking, and give them the address to copy. */
  function showFallback(btn, tier) {
    var note = fallbackNote(btn);
    if (!note) {
      note = document.createElement("p");
      note.className = "copy-fallback";
      note.setAttribute("role", "status");
      note.setAttribute("aria-live", "polite");
      btn.parentNode.appendChild(note);
    }
    note.textContent = "Your browser refused clipboard access. Copy " + ADDRESS +
      " by hand, or use the Email button above; the subject line is \u201c" + tier.subject + "\u201d.";
    note.hidden = false;
    relabel(btn, FAILED, RESTORE_AFTER * 2);
  }

  var dataNode = document.getElementById("intake-data");
  if (!dataNode) return;
  var intake = JSON.parse(dataNode.textContent);

  Array.prototype.forEach.call(document.querySelectorAll("button[data-tier]"), function (btn) {
    btn.addEventListener("click", function () {
      var tier = intake[btn.getAttribute("data-tier")];
      if (!tier) return;
      writeText(payloadFor(tier)).then(function () { flash(btn); }, function () { showFallback(btn, tier); });
    });
  });
})();
