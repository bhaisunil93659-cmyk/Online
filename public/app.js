let csrfToken = '';
const $ = (selector) => document.querySelector(selector);
const toast = $('#toast');
let toastTimer;

function notify(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
}

async function api(path, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  if (options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

async function refreshCsrf() {
  const result = await api('/api/csrf');
  csrfToken = result.csrfToken;
}

function showDashboard() {
  $('#login-view').classList.add('hidden');
  $('#dashboard-view').classList.remove('hidden');
}
function showLogin() {
  $('#dashboard-view').classList.add('hidden');
  $('#login-view').classList.remove('hidden');
}

async function loadDashboard() {
  const [settings, audit] = await Promise.all([api('/api/settings'), api('/api/audit')]);
  $('#destination').value = settings.call.destination || '';
  $('#condition').value = settings.call.condition || 'always';
  $('#call-toggle').checked = Boolean(settings.call.enabled);
  renderStatus();
  const list = $('#audit-list');
  list.className = audit.events.length ? '' : 'empty';
  list.replaceChildren();
  if (!audit.events.length) {
    list.textContent = 'No recent changes.';
    return;
  }
  audit.events.forEach((event) => {
    const item = document.createElement('div');
    item.className = 'audit-item';
    const title = document.createElement('span');
    title.textContent = event.action;
    const time = document.createElement('small');
    time.textContent = new Date(event.createdAt).toLocaleString();
    item.append(title, time);
    list.append(item);
  });
}

function renderStatus() {
  const enabled = $('#call-toggle').checked;
  $('#call-state').textContent = enabled ? `Requested: ${$('#condition').selectedOptions[0].text}` : 'Not enabled';
  $('#status-pill').textContent = enabled ? 'Preference enabled' : 'Not enabled';
  $('#status-pill').classList.toggle('off', !enabled);
}

async function initialize() {
  try {
    await refreshCsrf();
    await loadDashboard();
    showDashboard();
  } catch (error) {
    if (error.message === 'Unauthorized') showLogin();
    else showLogin();
  }
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const errorBox = $('#login-error');
  errorBox.textContent = '';
  try {
    await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('#username').value, password: $('#password').value })
    });
    $('#password').value = '';
    await refreshCsrf();
    await loadDashboard();
    showDashboard();
  } catch (error) {
    errorBox.textContent = error.message;
  }
});

$('#save-call').addEventListener('click', async () => {
  const destination = $('#destination').value.trim().replace(/[\s()-]/g, '');
  const enabled = $('#call-toggle').checked;
  if (enabled && !/^\+[1-9]\d{7,14}$/.test(destination)) {
    notify('Enter a valid international number you own.');
    $('#destination').focus();
    return;
  }
  try {
    await api('/api/settings/call', {
      method: 'PUT',
      body: JSON.stringify({ enabled, destination, condition: $('#condition').value })
    });
    await loadDashboard();
    notify('Preference saved. Your carrier settings were not changed.');
  } catch (error) { notify(error.message); }
});

$('#reset-call').addEventListener('click', async () => {
  $('#call-toggle').checked = false;
  renderStatus();
  try {
    await api('/api/settings/call', {
      method: 'PUT',
      body: JSON.stringify({ enabled: false, destination: '', condition: $('#condition').value })
    });
    await loadDashboard();
    notify('Preference turned off. Check your carrier separately to disable real forwarding.');
  } catch (error) { notify(error.message); }
});

$('#call-toggle').addEventListener('change', renderStatus);
$('#condition').addEventListener('change', renderStatus);
$('#logout').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
    await refreshCsrf();
    showLogin();
    notify('Signed out.');
  } catch (error) { notify(error.message); }
});

initialize();
