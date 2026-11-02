/**
 * Veridex AI - Options Page Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const optProtection = document.getElementById('opt-protection');
  const optModalWarning = document.getElementById('opt-modal-warning');
  const optNotifications = document.getElementById('opt-notifications');
  const optStrictMode = document.getElementById('opt-strict-mode');
  const optHoverScan = document.getElementById('opt-hover-scan');
  const btnSave = document.getElementById('btn-save');
  const saveStatus = document.getElementById('save-status');

  // Load existing settings
  chrome.storage.local.get('veridex_settings', (data) => {
    const s = data.veridex_settings || {};
    optProtection.checked = s.protectionEnabled !== false;
    optModalWarning.checked = s.showInPageWarning !== false;
    optNotifications.checked = s.desktopNotifications !== false;
    optStrictMode.checked = !!s.strictMode;
    optHoverScan.checked = !!s.scanOnHover;
  });

  // Save settings
  function saveSettings() {
    const settings = {
      protectionEnabled: optProtection.checked,
      showInPageWarning: optModalWarning.checked,
      desktopNotifications: optNotifications.checked,
      strictMode: optStrictMode.checked,
      scanOnHover: optHoverScan.checked
    };

    chrome.storage.local.set({ veridex_settings: settings }, () => {
      saveStatus.classList.add('show');
      setTimeout(() => {
        saveStatus.classList.remove('show');
      }, 2500);
    });
  }

  btnSave.addEventListener('click', saveSettings);
  [optProtection, optModalWarning, optNotifications, optStrictMode, optHoverScan].forEach(el => {
    el.addEventListener('change', saveSettings);
  });
});
