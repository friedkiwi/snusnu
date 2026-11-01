const csrf = document.querySelector('meta[name="csrf-token"]').content;
function b64decode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(s.padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));
}
function b64encode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function credentialJSON(credential, kind) {
  if (typeof credential.toJSON === 'function') return credential.toJSON();
  const response = credential.response;
  const common = {id: credential.id, rawId: b64encode(credential.rawId), type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults()};
  if (kind === 'register') {
    common.response = {clientDataJSON: b64encode(response.clientDataJSON),
      attestationObject: b64encode(response.attestationObject),
      transports: response.getTransports ? response.getTransports() : []};
  } else {
    common.response = {clientDataJSON: b64encode(response.clientDataJSON),
      authenticatorData: b64encode(response.authenticatorData), signature: b64encode(response.signature),
      userHandle: response.userHandle ? b64encode(response.userHandle) : null};
  }
  return common;
}
async function ceremony(kind) {
  if (!window.PublicKeyCredential) throw new Error('This browser does not support passkeys.');
  const prefix = kind === 'register' ? '/settings/passkey' : '/mfa/passkey';
  const begin = await fetch(prefix + '/begin', {method: 'POST', headers: {'X-CSRF-Token': csrf}});
  if (!begin.ok) throw new Error(await begin.text());
  const options = (await begin.json()).publicKey;
  let credential;
  if (kind === 'register') {
    if (PublicKeyCredential.parseCreationOptionsFromJSON) {
      credential = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)});
    } else {
      options.challenge = b64decode(options.challenge);
      options.user.id = b64decode(options.user.id);
      (options.excludeCredentials || []).forEach(x => x.id = b64decode(x.id));
      credential = await navigator.credentials.create({publicKey: options});
    }
  } else {
    if (PublicKeyCredential.parseRequestOptionsFromJSON) {
      credential = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options)});
    } else {
      options.challenge = b64decode(options.challenge);
      (options.allowCredentials || []).forEach(x => x.id = b64decode(x.id));
      credential = await navigator.credentials.get({publicKey: options});
    }
  }
  const finish = await fetch(prefix + '/finish', {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
    body: JSON.stringify(credentialJSON(credential, kind))});
  if (!finish.ok) throw new Error(await finish.text());
  location.href = kind === 'register' ? '/settings' : '/dashboard';
}
for (const [id, kind] of [['passkey-register', 'register'], ['passkey-login', 'login']]) {
  const button = document.getElementById(id);
  if (button) button.onclick = () => ceremony(kind).catch(e => document.getElementById('passkey-error').textContent = e.message);
}
