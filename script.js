/* ==========================================================================
   ARCHITECTURE OF TRUST — Validation Engine
   Implements the 4-phase model from the project brief:
   1. Structure  (HTML)   — semantic form markup (see index.html)
   2. Shield     (JS)     — intercept submit, prevent default reload
   3. Scan       (Regex)  — pattern-match every payload field
   4. Communicate (ARIA)  — wire errors to inputs for assistive tech
   ========================================================================== */

(function () {
  "use strict";

  /* ----------------------------------------------------------------------
     Regex Logic Gates
     The password and email patterns are specified exactly in the brief —
     reproduced verbatim rather than approximated.
     ---------------------------------------------------------------------- */
  const PATTERNS = {
    // Simple syntax check: text@text.text — guards the gate without
    // rejecting legitimate addresses RFC 5322 would otherwise allow.
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,

    // Name: letters, spaces, hyphens, apostrophes — at least 2 characters.
    fullName: /^[A-Za-z][A-Za-z\s'-]{1,}$/,

    // 10–15 digits, optionally separated by spaces/dashes, optional leading +.
    phone: /^\+?[0-9]{10,15}$/,
    phoneStrip: /[\s-]/g,

    // Strict password policy, exactly as specified:
    // one uppercase, one lowercase, one digit, one special char, 8+ length.
    password: /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/,
  };

  const RULE_CHECKS = {
    length:  (v) => v.length >= 8,
    upper:   (v) => /[A-Z]/.test(v),
    lower:   (v) => /[a-z]/.test(v),
    digit:   (v) => /[0-9]/.test(v),
    special: (v) => /[#?!@$%^&*-]/.test(v),
  };

  /* ----------------------------------------------------------------------
     DOM references
     ---------------------------------------------------------------------- */
  const form = document.getElementById("checkpointForm");
  const submitBtn = document.getElementById("submitBtn");
  const formBanner = document.getElementById("formBanner");
  const srAnnouncer = document.getElementById("srAnnouncer");
  const payloadCode = document.getElementById("payloadCode");

  const fields = ["fullName", "email", "phone", "password", "confirmPassword"]
    .map((name) => ({
      name,
      input: document.getElementById(name),
      fieldEl: document.querySelector(`.field[data-field="${name}"]`),
      errorEl: document.getElementById(`${name}-error`),
      ledgerRow: document.querySelector(`.ledger-row[data-ledger="${name}"] .ledger-state`),
    }));

  const fieldByName = Object.fromEntries(fields.map((f) => [f.name, f]));

  /* ----------------------------------------------------------------------
     Per-field validators
     Each returns "" (valid) or an error message (invalid).
     ---------------------------------------------------------------------- */
  function validateFullName(value) {
    const v = value.trim();
    if (v === "") return "Full name is required.";
    if (v.length < 2) return "Name must be at least 2 characters.";
    if (!PATTERNS.fullName.test(v)) return "Use letters only (hyphens and apostrophes allowed).";
    return "";
  }

  function validateEmail(value) {
    const v = value.trim();
    if (v === "") return "Email address is required.";
    if (!PATTERNS.email.test(v)) return "Enter a valid email, like name@domain.com.";
    return "";
  }

  function validatePhone(value) {
    const v = value.trim();
    if (v === "") return "Phone number is required.";
    const stripped = v.replace(PATTERNS.phoneStrip, "");
    if (!PATTERNS.phone.test(stripped)) return "Enter 10–15 digits, e.g. +92 300 1234567.";
    return "";
  }

  function validatePassword(value) {
    if (value === "") return "Password is required.";
    if (!RULE_CHECKS.length(value))  return "Password must be at least 8 characters long.";
    if (!RULE_CHECKS.upper(value))   return "Password must contain at least one uppercase letter.";
    if (!RULE_CHECKS.lower(value))   return "Password must contain at least one lowercase letter.";
    if (!RULE_CHECKS.digit(value))   return "Password must contain at least one number.";
    if (!RULE_CHECKS.special(value)) return "Password must contain at least one special character from [#?!@$%^&*-].";
    // Final confirmation against the full pattern (defense in depth).
    if (!PATTERNS.password.test(value)) return "Password does not meet the required policy.";
    return "";
  }

  function validateConfirmPassword(value) {
    const pwd = fieldByName.password.input.value;
    if (value === "") return "Please confirm your password.";
    if (value !== pwd) return "Passwords do not match.";
    return "";
  }

  const VALIDATORS = {
    fullName: validateFullName,
    email: validateEmail,
    phone: validatePhone,
    password: validatePassword,
    confirmPassword: validateConfirmPassword,
  };

  /* ----------------------------------------------------------------------
     UI updates — apply validation result to the DOM + ARIA tether
     ---------------------------------------------------------------------- */
  function applyResult(field, message, opts = {}) {
    const { silent = false } = opts;
    const isValid = message === "";

    field.fieldEl.classList.toggle("is-valid", isValid);
    field.fieldEl.classList.toggle("is-invalid", !isValid);
    field.input.setAttribute("aria-invalid", String(!isValid));
    field.errorEl.textContent = isValid ? "" : message;

    if (field.ledgerRow) {
      field.ledgerRow.dataset.state = isValid ? "pass" : "fail";
      field.ledgerRow.textContent = isValid ? "Approved" : "Rejected";
    }

    if (!silent) {
      announce(isValid ? `${labelFor(field.name)} approved.` : `${labelFor(field.name)}: ${message}`);
    }
  }

  function resetFieldUI(field) {
    field.fieldEl.classList.remove("is-valid", "is-invalid");
    field.input.setAttribute("aria-invalid", "false");
    field.errorEl.textContent = "";
    if (field.ledgerRow) {
      field.ledgerRow.dataset.state = "idle";
      field.ledgerRow.textContent = "Awaiting input";
    }
  }

  function labelFor(name) {
    return {
      fullName: "Full name",
      email: "Email address",
      phone: "Phone number",
      password: "Password",
      confirmPassword: "Confirm password",
    }[name];
  }

  function announce(message) {
    srAnnouncer.textContent = "";
    // Re-trigger so repeated identical messages still get announced.
    window.requestAnimationFrame(() => { srAnnouncer.textContent = message; });
  }

  function runValidation(name, opts) {
    const field = fieldByName[name];
    const message = VALIDATORS[name](field.input.value);
    applyResult(field, message, opts);
    return message === "";
  }

  /* ----------------------------------------------------------------------
     Live password policy checklist
     ---------------------------------------------------------------------- */
  const policyItems = document.querySelectorAll("#password-hint li");
  function updatePolicyChecklist(value) {
    policyItems.forEach((li) => {
      const rule = li.dataset.rule;
      const met = RULE_CHECKS[rule](value);
      li.classList.toggle("met", met);
    });
  }

  /* ----------------------------------------------------------------------
     Event wiring
     - Validate on blur (not on every keystroke) so screen reader users
       and the aria-live region aren't interrupted mid-typing.
     - Password gets a live checklist update on input for visual users,
       but the formal pass/fail + announcement still happens on blur.
     ---------------------------------------------------------------------- */
  fields.forEach((field) => {
    field.input.addEventListener("blur", () => {
      if (field.input.value.trim() !== "" || field.fieldEl.dataset.touched === "true") {
        field.fieldEl.dataset.touched = "true";
        runValidation(field.name);
      }
    });

    field.input.addEventListener("input", () => {
      // Clear an existing error state as soon as the user starts correcting it,
      // but don't re-announce or re-validate until they blur again.
      if (field.fieldEl.classList.contains("is-invalid") && field.input.value.trim() === "") {
        resetFieldUI(field);
      }
      if (field.name === "password") {
        updatePolicyChecklist(field.input.value);
        // Live-sync confirm password if it was already touched.
        if (fieldByName.confirmPassword.fieldEl.dataset.touched === "true") {
          runValidation("confirmPassword", { silent: true });
        }
      }
    });
  });

  /* ----------------------------------------------------------------------
     Password visibility toggles
     ---------------------------------------------------------------------- */
  document.querySelectorAll(".toggle-visibility").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.dataset.target);
      const showing = target.type === "text";
      target.type = showing ? "password" : "text";
      btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    });
  });

  /* ----------------------------------------------------------------------
     Submit — the Shield phase
     ---------------------------------------------------------------------- */
  form.addEventListener("submit", function (event) {
    event.preventDefault(); // Stop the default HTTP reload / memory wipe.

    let allValid = true;
    fields.forEach((field) => {
      field.fieldEl.dataset.touched = "true";
      const ok = runValidation(field.name, { silent: true });
      if (!ok) allValid = false;
    });

    if (!allValid) {
      showBanner("fail", "Some fields need attention before this can be submitted. Check the highlighted fields above.");
      announce("Form submission blocked. One or more fields failed validation.");
      const firstInvalid = fields.find((f) => f.fieldEl.classList.contains("is-invalid"));
      if (firstInvalid) firstInvalid.input.focus();
      return;
    }

    // All gates passed — package the approved payload.
    const payload = {
      fullName: fieldByName.fullName.input.value.trim(),
      email: fieldByName.email.input.value.trim(),
      phone: fieldByName.phone.input.value.trim(),
      password: "••••••••", // never display the real password back to the user
    };

    payloadCode.textContent = JSON.stringify(payload, null, 2);
    showBanner("success", "All checks passed. Your request has been validated and packaged for submission.");
    announce("Form submitted successfully. All fields passed validation.");
  });

  function showBanner(type, message) {
    formBanner.classList.remove("success", "fail", "show");
    formBanner.textContent = message;
    formBanner.classList.add(type, "show");
  }

})();