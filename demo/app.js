/**
 * Decentralized Identity Provider - OAuth 2.0 / OIDC Authorization Flow Demo
 * Simulating MPC (Multi-Party Computation), TOPRF, and FROST EdDSA Threshold Signatures on PASTA Curves
 */

// State Management
const state = {
  currentStep: 1,
  user: {
    email: 'alice@zk-auth.network',
    name: 'Alice Nakamoto',
    did: 'did:pasta:z6MkqBq4b...',
    sub: 'usr_8f20b8e914cb'
  },
  client: {
    name: 'ZK-App Portal',
    clientId: 'zk_portal_client_prod_882',
    redirectUri: 'https://portal.zk-app.example/oauth/callback',
    state: 'xyz_sec_token_98765',
    nonce: 'nonce_random_991823'
  },
  scopes: {
    openid: true,
    profile: true,
    email: true,
    offline_access: false,
    'pasta:zk_claims': true
  },
  nodes: [
    { id: 1, name: 'Node 1 (Tokyo)', region: 'ap-northeast-1', ip: '198.51.100.12', status: 'ready', latency: 18, share: null },
    { id: 2, name: 'Node 2 (Frankfurt)', region: 'eu-central-1', ip: '198.51.100.45', status: 'ready', latency: 42, share: null },
    { id: 3, name: 'Node 3 (Oregon)', region: 'us-west-2', ip: '198.51.100.89', status: 'ready', latency: 64, share: null }
  ],
  generatedToken: null,
  isProcessing: false
};

// Preset demo accounts
const PRESET_ACCOUNTS = {
  alice: {
    email: 'alice@zk-auth.network',
    password: '••••••••••••',
    name: 'Alice Nakamoto',
    did: 'did:pasta:z6MkqBq4bH7Kx9Y1N8P3',
    sub: 'usr_8f20b8e914cb'
  },
  bob: {
    email: 'bob.validator@enterprise.io',
    password: '••••••••••••',
    name: 'Bob Vance',
    did: 'did:pasta:z6MksV7Jq89X20LmQ3rT',
    sub: 'usr_4a91c0e271bf'
  }
};

// Helper: Base64URL encode
function base64UrlEncode(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Helper: Fake cryptographic hash string
function fakeCryptoHex(length = 32) {
  const chars = '0123456789abcdef';
  let res = '';
  for (let i = 0; i < length; i++) {
    res += chars[Math.floor(Math.random() * chars.length)];
  }
  return res;
}

// DOM Elements
const step1 = document.getElementById('step-1-login');
const step2 = document.getElementById('step-2-consent');
const step3 = document.getElementById('step-3-mpc');
const step4 = document.getElementById('step-4-success');
const terminalLogs = document.getElementById('terminal-logs');
const progressBar = document.getElementById('mpc-progress-bar');
const progressPercentage = document.getElementById('mpc-progress-pct');
const statusBadge = document.getElementById('mpc-overall-status');

// Navigation between steps
function showStep(stepNumber) {
  state.currentStep = stepNumber;
  const steps = [step1, step2, step3, step4];
  
  steps.forEach((el, index) => {
    if (index + 1 === stepNumber) {
      el.classList.remove('hidden-pane');
      el.classList.add('active-pane');
    } else {
      el.classList.add('hidden-pane');
      el.classList.remove('active-pane');
    }
  });

  // Update Breadcrumb/Indicator dots
  for (let i = 1; i <= 4; i++) {
    const indicator = document.getElementById(`step-indicator-${i}`);
    const line = document.getElementById(`step-line-${i}`);
    if (indicator) {
      if (i < stepNumber) {
        indicator.className = 'w-8 h-8 rounded-full bg-emerald-500 text-white flex items-center justify-center font-bold text-xs shadow-lg shadow-emerald-500/20';
        indicator.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`;
      } else if (i === stepNumber) {
        indicator.className = 'w-8 h-8 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-xs ring-4 ring-indigo-500/30 shadow-lg shadow-indigo-600/30';
        indicator.innerText = i;
      } else {
        indicator.className = 'w-8 h-8 rounded-full bg-gray-800 text-gray-400 border border-gray-700 flex items-center justify-center font-bold text-xs';
        indicator.innerText = i;
      }
    }
    if (line) {
      line.className = i < stepNumber ? 'h-0.5 w-12 bg-emerald-500 transition-colors' : 'h-0.5 w-12 bg-gray-700 transition-colors';
    }
  }
}

// Log message to terminal
function addTerminalLog(message, type = 'info') {
  if (!terminalLogs) return;
  const now = new Date();
  const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(now.getMilliseconds()).padStart(3, '0')}`;
  
  let colorClass = 'text-gray-300';
  let badge = 'INFO';
  if (type === 'crypto') {
    colorClass = 'text-indigo-400 font-mono';
    badge = 'CRYPTO';
  } else if (type === 'network') {
    colorClass = 'text-cyan-400 font-mono';
    badge = 'P2P';
  } else if (type === 'success') {
    colorClass = 'text-emerald-400 font-semibold font-mono';
    badge = 'SUCCESS';
  } else if (type === 'warn') {
    colorClass = 'text-amber-400 font-mono';
    badge = 'WARN';
  }

  const logLine = document.createElement('div');
  logLine.className = 'text-xs py-0.5 flex items-start gap-2 leading-relaxed';
  logLine.innerHTML = `
    <span class="text-gray-500 select-none">[${timeStr}]</span>
    <span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 border border-gray-700 font-mono text-gray-400 select-none">${badge}</span>
    <span class="${colorClass}">${message}</span>
  `;
  terminalLogs.appendChild(logLine);
  terminalLogs.scrollTop = terminalLogs.scrollHeight;
}

// Preset Account Selection
window.selectPresetAccount = function(key) {
  const account = PRESET_ACCOUNTS[key];
  if (!account) return;
  
  const emailInput = document.getElementById('login-email');
  const passwordInput = document.getElementById('login-password');
  if (emailInput) emailInput.value = account.email;
  if (passwordInput) passwordInput.value = account.password;
  
  state.user = {
    email: account.email,
    name: account.name,
    did: account.did,
    sub: account.sub
  };
  
  // Update badges on UI
  const selectedBadge = document.getElementById('selected-account-label');
  if (selectedBadge) {
    selectedBadge.innerText = `${account.name} (${account.email})`;
  }
};

// Handle Login Form Submit
document.getElementById('login-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const emailVal = document.getElementById('login-email').value;
  if (emailVal) {
    state.user.email = emailVal;
    if (emailVal.includes('bob')) {
      state.user.name = 'Bob Vance';
      state.user.did = PRESET_ACCOUNTS.bob.did;
      state.user.sub = PRESET_ACCOUNTS.bob.sub;
    } else {
      state.user.name = 'Alice Nakamoto';
      state.user.did = PRESET_ACCOUNTS.alice.did;
      state.user.sub = PRESET_ACCOUNTS.alice.sub;
    }
  }

  // Update Consent Screen Display
  document.getElementById('consent-user-name').innerText = state.user.name;
  document.getElementById('consent-user-email').innerText = state.user.email;
  document.getElementById('consent-user-did').innerText = state.user.did;

  showStep(2);
});

// Consent Cancellation
window.handleCancelConsent = function() {
  if (confirm('認証連携をキャンセルしますか？クライアント画面に戻ります。')) {
    alert('認可リクエストが拒否されました (error=access_denied)');
    showStep(1);
  }
};

// Scope Toggles Sync
function syncScopes() {
  document.querySelectorAll('.scope-toggle').forEach(input => {
    const scopeKey = input.dataset.scope;
    if (scopeKey) {
      state.scopes[scopeKey] = input.checked;
    }
  });
}

// Node UI Status Update
function updateNodeUI(nodeId, status, detailText, badgeClass) {
  const card = document.getElementById(`node-card-${nodeId}`);
  const statusEl = document.getElementById(`node-status-${nodeId}`);
  const detailEl = document.getElementById(`node-detail-${nodeId}`);

  if (card) {
    if (status === 'computing') {
      card.classList.add('node-computing', 'border-indigo-500/70');
      card.classList.remove('border-gray-700', 'border-emerald-500/70');
    } else if (status === 'success') {
      card.classList.remove('node-computing', 'border-indigo-500/70');
      card.classList.add('border-emerald-500/70');
    } else {
      card.classList.remove('node-computing', 'border-indigo-500/70', 'border-emerald-500/70');
      card.classList.add('border-gray-700');
    }
  }

  if (statusEl) {
    statusEl.className = `text-[11px] px-2 py-0.5 rounded-full font-semibold ${badgeClass}`;
    statusEl.innerText = status.toUpperCase();
  }

  if (detailEl && detailText) {
    detailEl.innerText = detailText;
  }
}

// Generate Real EdDSA / OIDC JWT Token
function generateMockEdDSAJwt() {
  const header = {
    alg: "EdDSA",
    crv: "Ed25519",
    typ: "JWT",
    kid: "pasta-frost-idp-key-2026",
    mpc_threshold: "2-of-3"
  };

  const nowSec = Math.floor(Date.now() / 1000);
  const selectedScopeList = Object.keys(state.scopes).filter(k => state.scopes[k]);

  const payload = {
    iss: "https://idp.pasta-auth.network",
    sub: state.user.sub,
    aud: state.client.clientId,
    exp: nowSec + 3600,
    nbf: nowSec,
    iat: nowSec,
    auth_time: nowSec,
    nonce: state.client.nonce,
    did: state.user.did,
    scope: selectedScopeList.join(' '),
    amr: ["pwd", "mpc_toprf", "frost_threshold_eddsa"],
    curve: "Pallas/Vesta",
    zk_blind_commitment: "0x" + fakeCryptoHex(24)
  };

  if (state.scopes.profile) {
    payload.name = state.user.name;
    payload.preferred_username = state.user.email.split('@')[0];
  }
  if (state.scopes.email) {
    payload.email = state.user.email;
    payload.email_verified = true;
  }
  if (state.scopes['pasta:zk_claims']) {
    payload.zk_identity_commitment = "0x" + fakeCryptoHex(32);
    payload.frost_quorum_participants = [1, 2];
  }

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  // Deterministic looking high entropy EdDSA signature
  const encodedSig = base64UrlEncode(`sig_frost_eddsa_${fakeCryptoHex(64)}`);

  return {
    raw: `${encodedHeader}.${encodedPayload}.${encodedSig}`,
    header,
    payload,
    signature: encodedSig,
    parts: {
      header: encodedHeader,
      payload: encodedPayload,
      signature: encodedSig
    }
  };
}

// Interactive MPC / TOPRF / FROST Execution Simulation
async function startMpcAuthorization() {
  syncScopes();
  showStep(3);
  state.isProcessing = true;
  
  if (terminalLogs) terminalLogs.innerHTML = '';
  if (progressBar) progressBar.style.width = '5%';
  if (progressPercentage) progressPercentage.innerText = '5%';
  if (statusBadge) {
    statusBadge.innerText = 'Initializing MPC Session';
    statusBadge.className = 'text-xs px-2.5 py-1 rounded-full bg-indigo-900/60 text-indigo-300 border border-indigo-700';
  }

  // Reset Node Cards
  [1, 2, 3].forEach(id => {
    updateNodeUI(id, 'ready', 'Standby for TOPRF blind input...', 'bg-gray-800 text-gray-400');
  });

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  // Step A: Client Blinding
  addTerminalLog('Initiating Decentralized OAuth2 Authorization session...', 'info');
  addTerminalLog(`Target Client: ${state.client.name} (${state.client.clientId})`, 'info');
  await sleep(350);

  addTerminalLog('[Client-side] Generating blind scalar r ∈ 𝔽_q for user credentials...', 'crypto');
  addTerminalLog(`[PASTA Curve] Map user password hash to Pallas curve base point P = HashToCurve(pwd)`, 'crypto');
  progressBar.style.width = '20%';
  progressPercentage.innerText = '20%';
  statusBadge.innerText = 'Step 1: Blinding & Node Dispatch';
  await sleep(400);

  // Step B: Dispatch to Nodes
  addTerminalLog('Broadcasting blinded query P\' = r * P to 3 independent IdP threshold nodes...', 'network');
  [1, 2, 3].forEach(id => {
    updateNodeUI(id, 'computing', 'Evaluating TOPRF share (Pallas curve exponentiation)...', 'bg-indigo-900 text-indigo-200');
  });
  progressBar.style.width = '35%';
  progressPercentage.innerText = '35%';
  await sleep(550);

  // Node 1 completes
  addTerminalLog('Node 1 (Tokyo 🇯🇵): Share 1 computed in 18ms. Beaver triple generated.', 'network');
  updateNodeUI(1, 'success', 'Share 1 Ready: H_1 = k_1 * P\' (Signed)', 'bg-emerald-900/80 text-emerald-200');
  progressBar.style.width = '50%';
  progressPercentage.innerText = '50%';
  await sleep(400);

  // Node 2 completes (Threshold 2-of-3 satisfied!)
  addTerminalLog('Node 2 (Frankfurt 🇩🇪): Share 2 computed in 42ms. Quorum (2/3) achieved!', 'network');
  updateNodeUI(2, 'success', 'Share 2 Ready: H_2 = k_2 * P\' (Signed)', 'bg-emerald-900/80 text-emerald-200');
  progressBar.style.width = '70%';
  progressPercentage.innerText = '70%';
  statusBadge.innerText = 'Step 2: Lagrange Interpolation & FROST Round 2';
  await sleep(450);

  // Node 3 also arrives
  addTerminalLog('Node 3 (Oregon 🇺🇸): Share 3 received (redundancy check OK).', 'network');
  updateNodeUI(3, 'success', 'Share 3 Ready: verified', 'bg-emerald-900/80 text-emerald-200');
  progressBar.style.width = '85%';
  progressPercentage.innerText = '85%';
  await sleep(350);

  // Step C: FROST Threshold Signature Assembly
  addTerminalLog('[Client Unblinding] Unblinding aggregated PRF output with r⁻¹...', 'crypto');
  addTerminalLog('[FROST Protocol] Assembling EdDSA threshold signature via Lagrange coefficient weights...', 'crypto');
  addTerminalLog('[Decentralized IdP] Signature verified against public identity key (IdP never saw plaintext!)', 'success');
  progressBar.style.width = '100%';
  progressPercentage.innerText = '100%';
  statusBadge.innerText = 'Step 3: EdDSA JWT Minted Successfully';
  statusBadge.className = 'text-xs px-2.5 py-1 rounded-full bg-emerald-900/60 text-emerald-300 border border-emerald-600';
  await sleep(500);

  // Generate Token & Show Step 4
  const jwt = generateMockEdDSAJwt();
  state.generatedToken = jwt;

  renderTokenDisplay(jwt);
  showStep(4);
  state.isProcessing = false;
}

// Render Token Details in Step 4
function renderTokenDisplay(jwt) {
  // Color-coded raw JWT
  const rawContainer = document.getElementById('jwt-colored-display');
  if (rawContainer) {
    rawContainer.innerHTML = `
      <span class="jwt-part-header font-mono">${jwt.parts.header}</span>
      <span class="jwt-part-dot">.</span>
      <span class="jwt-part-payload font-mono">${jwt.parts.payload}</span>
      <span class="jwt-part-dot">.</span>
      <span class="jwt-part-sig font-mono">${jwt.parts.signature}</span>
    `;
  }

  // JSON Previews
  const headerJsonEl = document.getElementById('jwt-header-json');
  const payloadJsonEl = document.getElementById('jwt-payload-json');
  
  if (headerJsonEl) {
    headerJsonEl.innerText = JSON.stringify(jwt.header, null, 2);
  }
  if (payloadJsonEl) {
    payloadJsonEl.innerText = JSON.stringify(jwt.payload, null, 2);
  }

  // Summary labels
  const tokenSubEl = document.getElementById('token-summary-sub');
  const tokenAudEl = document.getElementById('token-summary-aud');
  const tokenExpEl = document.getElementById('token-summary-exp');

  if (tokenSubEl) tokenSubEl.innerText = jwt.payload.sub;
  if (tokenAudEl) tokenAudEl.innerText = jwt.payload.aud;
  if (tokenExpEl) tokenExpEl.innerText = new Date(jwt.payload.exp * 1000).toLocaleTimeString();
}

// Copy JWT to Clipboard
window.copyJwtToClipboard = function() {
  if (!state.generatedToken) return;
  navigator.clipboard.writeText(state.generatedToken.raw).then(() => {
    const copyBtn = document.getElementById('copy-token-btn');
    if (copyBtn) {
      const originalHtml = copyBtn.innerHTML;
      copyBtn.innerHTML = `
        <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
        <span class="text-emerald-400 font-medium">Copied!</span>
      `;
      setTimeout(() => {
        copyBtn.innerHTML = originalHtml;
      }, 2000);
    }
  });
};

// Simulate RP Callback / Redirect
window.simulateRpRedirect = function() {
  const code = 'authcode_' + fakeCryptoHex(16);
  const redirectUrl = `${state.client.redirectUri}?code=${code}&state=${state.client.state}`;
  
  const modal = document.getElementById('rp-callback-modal');
  const rpUrlEl = document.getElementById('rp-redirect-target-url');
  const rpUserEl = document.getElementById('rp-received-user');
  const rpSubEl = document.getElementById('rp-received-sub');
  const rpTokenSnippetEl = document.getElementById('rp-token-snippet');

  if (rpUrlEl) rpUrlEl.innerText = redirectUrl;
  if (rpUserEl) rpUserEl.innerText = `${state.user.name} (${state.user.email})`;
  if (rpSubEl) rpSubEl.innerText = state.user.sub;
  if (rpTokenSnippetEl && state.generatedToken) {
    rpTokenSnippetEl.innerText = state.generatedToken.raw.substring(0, 50) + '...';
  }

  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
};

window.closeRpModal = function() {
  const modal = document.getElementById('rp-callback-modal');
  if (modal) {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
};

// Technical Details Modal
window.toggleTechModal = function(show) {
  const modal = document.getElementById('tech-details-modal');
  if (modal) {
    if (show) {
      modal.classList.remove('hidden');
      modal.classList.add('flex');
    } else {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
  }
};

// Restart Flow
window.resetFlow = function() {
  showStep(1);
};

// Start consent button listener
document.getElementById('start-auth-btn')?.addEventListener('click', () => {
  startMpcAuthorization();
});

// Initialize first step
document.addEventListener('DOMContentLoaded', () => {
  showStep(1);
});
