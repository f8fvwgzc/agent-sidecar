// The sign-in screen: a token is exchanged for the session cookie (POST /login). The token is
// sent once and never stored by the console; the field is cleared after every attempt.

import { $ } from './dom.js';
import { TOKEN_RE } from './util.js';

let wired = false;
let handler = null;

function showError(msg) {
  const el = $('#signin-error');
  el.textContent = msg || '';
  el.hidden = !msg;
}

export function showSignin({ api, message, onSignedIn }) {
  handler = { api, onSignedIn };
  $('#app').hidden = true;
  $('#signin').hidden = false;
  const note = $('#signin-note');
  note.textContent = message || '';
  note.hidden = !message;
  showError('');
  const input = $('#token');
  input.value = '';
  setTimeout(() => input.focus(), 0);
  if (wired) return;
  wired = true;
  $('#signin-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const input2 = $('#token');
    const token = input2.value.trim();
    input2.value = '';
    if (!TOKEN_RE.test(token)) {
      showError('That is not an access token: it starts with att_ followed by 43 characters.');
      return;
    }
    const btn = $('#signin-submit');
    btn.disabled = true;
    showError('');
    try {
      const res = await handler.api.login(token);
      $('#signin').hidden = true;
      await handler.onSignedIn(res.data);
    } catch (e) {
      if (e.status === 429) showError(`Too many failed attempts. ${e.details[0] || 'Try again in a minute.'}`);
      else if (e.status === 401 || e.status === 400) showError('The control plane did not accept this token.');
      else if (e.status === 421) showError('This host name is not served by the control plane (421). Use one of its --dns-name values.');
      else showError(`Sign-in failed: ${e.code || e.message}`);
      input2.focus();
    } finally {
      btn.disabled = false;
    }
  });
}

export function hideSignin() {
  $('#signin').hidden = true;
}
