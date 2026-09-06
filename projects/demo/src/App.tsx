import { useState } from 'react';
import { Shield, Key, Lock, CheckCircle2, RefreshCw, ArrowRight, Server, Copy, AlertTriangle } from 'lucide-react';
import { DecentralizedClientSdk } from './sdk/client';
import type { DemoEvent } from './sdk/events';

interface NodeStatus {
  id: number;
  name: string;
  region: string;
  state: 'idle' | 'sending' | 'evaluating' | 'encrypted' | 'success';
}

/**
 * The one journey the audience follows, shared verbatim with the rp pages
 * (projects/rp/src/html.ts). Six stages that cross two origins: the rp front end
 * (localhost:3001) owns stages 1 and 4-6, the IdP (localhost:3000) owns 2-3.
 */
const FLOW_STEPS: { label: string; sub: string; origin: 'rp' | 'idp' }[] = [
  { label: 'ログイン開始', sub: 'localhost:3001', origin: 'rp' },
  { label: 'IdP で認証', sub: 'PASTA', origin: 'idp' },
  { label: 'アサーション発行', sub: 'code', origin: 'idp' },
  { label: 'RP へ戻る', sub: 'redirect', origin: 'rp' },
  { label: 'トークン交換', sub: 'DPoP', origin: 'rp' },
  { label: 'トークン取得', sub: 'access_token', origin: 'rp' },
];

/**
 * The cross-origin progress bar. `current` is the 1-based stage this page is on;
 * earlier stages read as done, later ones as upcoming. The marker hue names the origin
 * that owns the stage (rp = blue, IdP = violet), so the audience sees the flow cross
 * from blue to violet and back. The rp pages render the same six stages in plain CSS.
 */
function FlowStepper({ current }: { current: number }) {
  return (
    <nav aria-label="フロー全体の進行" className="w-full max-w-4xl mx-auto">
      <ol className="flex items-start">
        {FLOW_STEPS.map((s, i) => {
          const n = i + 1;
          const state = n < current ? 'done' : n === current ? 'current' : 'upcoming';
          const isRp = s.origin === 'rp';
          const marker =
            state === 'current'
              ? isRp
                ? 'bg-blue-500 border-blue-400 text-white shadow-lg shadow-blue-500/40 ring-4 ring-blue-500/20'
                : 'bg-violet-500 border-violet-400 text-white shadow-lg shadow-violet-500/40 ring-4 ring-violet-500/20'
              : state === 'done'
              ? isRp
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-violet-500/10 border-violet-500/50 text-violet-300'
              : 'bg-slate-900 border-slate-700 text-slate-600';
          const labelCls =
            state === 'current'
              ? 'text-white font-semibold'
              : state === 'done'
              ? 'text-slate-300'
              : 'text-slate-600';
          return (
            <li key={n} className="flex-1 flex flex-col items-center relative min-w-0">
              {n > 1 && (
                <span
                  className={`absolute top-4 right-1/2 h-0.5 w-full z-0 ${
                    n <= current ? 'bg-slate-500' : 'bg-slate-800'
                  }`}
                />
              )}
              <span
                className={`relative z-10 w-8 h-8 rounded-full border flex items-center justify-center text-xs font-bold transition-all ${marker}`}
              >
                {state === 'done' ? '✓' : n}
              </span>
              <span className={`mt-2 text-[11px] leading-tight text-center px-1 ${labelCls}`}>
                {s.label}
              </span>
              <span className="mt-0.5 text-[9px] font-mono text-slate-500 text-center leading-none">
                {s.sub}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/** Split a JWT into header / payload / signature for the viewer tab. */
function decodeJwt(token: string): { header: any; payload: any; signature: string } | null {
  try {
    const parts = token.split('.');
    const parseB64 = (s: string) =>
      JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    return { header: parseB64(parts[0]), payload: parseB64(parts[1]), signature: parts[2] };
  } catch {
    return null;
  }
}

export default function App() {
  const urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const rawStep = urlParams?.get('step') || 'login';
  const initialStep = rawStep === 'jwt' ? 'completed' : (rawStep as any);
  const initialTab = rawStep === 'jwt' ? 'jwt' : (urlParams?.get('tab') as any) || 'visualizer';

  // OAuth 認可コードフロー連携パラメータ (docs/container-split.md 第 14.1 節)
  // rp フロント → gateway /authorize → gateway が /demo?c&dpop_jkt&client_id&redirect_uri&scope&state へ引き継ぐ
  const oauthRedirectUri = urlParams?.get('redirect_uri') || null;
  const oauthClientId = urlParams?.get('client_id') || 'demo_client';
  const oauthScope = urlParams?.get('scope') || 'openid profile';
  // The authorize challenge `c`. It becomes the assertion's `nonce`, so a node can bind the
  // authorization code to this authorize step. Without it there is no code to make.
  const oauthChallenge = urlParams?.get('c') || null;
  const oauthState = urlParams?.get('state') || '';
  // docs/container-split.md section 13: the DPoP key pair belongs to the rp front end.
  // This page never makes one -- it only receives the thumbprint that /authorize carried
  // through, and binds the assertion to it. Without it there is nothing to bind to.
  const oauthDpopJkt = urlParams?.get('dpop_jkt') || null;
  // The flow only starts when the rp front end supplied all three: the DPoP thumbprint to
  // bind to, the authorize challenge to sign, and where to send the code back.
  const flowReady = Boolean(oauthDpopJkt && oauthChallenge && oauthRedirectUri);
  const MISSING_FLOW_MESSAGE =
    'rp から必要なパラメータ (dpop_jkt / c / redirect_uri) が渡されていません。' +
    'http://localhost:3001/ から開始してください。';

  // Screenshot-only mock (`?step=completed`). A section 14 authentication assertion: the
  // signature bytes are not real, and the on-screen banner says so.
  const defaultMockToken =
    'eyJhbGciOiJFZERTQSIsImtpZCI6InBhc3RhLWdyb3VwLWtleS0xIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjbGllbnRfaWQiOiJkZW1vX2NsaWVudCIsImNuZiI6eyJqa3QiOiI2Y1BRTkltZmJocW1qSHo1WEQ5VTgyNnVaWUw1S1I1U205Ym0zTnVRWE0ifSwiZXhwIjoxNzU3MDMwNDMwLCJpYXQiOjE3NTcwMzA0MDAsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsIm5vbmNlIjoiY19kZW1vXzlmM2MxYTIwIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSIsInN1YiI6InVzcl9hbGljZV8xMjM0NSJ9.Zqx3demo_group_signature_for_screenshot_only_not_verifiable_bytes';

  const [step, setStep] = useState<'login' | 'consent' | 'signing' | 'completed'>(initialStep);
  const [username, setUsername] = useState('alice');
  const [password, setPassword] = useState('password123');
  const [assertion, setAssertion] = useState<string | null>(initialStep === 'completed' ? defaultMockToken : null);
  const [decodedToken, setDecodedToken] = useState<any>(
    initialStep === 'completed'
      ? {
          header: { alg: 'EdDSA', typ: 'JWT', kid: 'pasta-group-key-1' },
          payload: {
            iss: 'http://localhost:3000',
            sub: 'usr_alice_12345',
            aud: 'http://localhost:3000',
            client_id: 'demo_client',
            scope: 'openid profile',
            nonce: 'c_demo_9f3c1a20',
            iat: 1757030400,
            exp: 1757030430,
            cnf: { jkt: '6cPQNImfbhqmjHz5XD9U826uZYL5KR5Sm9bm3NuQXM' },
          },
        }
      : null
  );
  const [logs, setLogs] = useState<string[]>(
    initialStep === 'completed'
      ? [
          '分散サインオン処理を開始します (PASTA + FROST)...',
          'rp フロントから受け取った DPoP サムプリントに束縛: cnf.jkt = 6cPQNImfbhqmjHz5XD9U826uZYL5KR5Sm9bm3NuQXM',
          'ブラウザ内でパスワードを目隠し暗号化: A = r * H1(pw) (Ristretto255群)...',
          '各ノードがパスワードを検証することなく 2HashTDH 部分評価値 B_i を計算完了',
          '各ノードがFROST署名シェア z_i を生成し、h_i で暗号化完了',
          'クライアント端末で暗号文 ct_i を復号成功（正しいパスワード所持の暗号学的証明）',
          'ラグランジュ補間係数を用いてFROST Schnorr署名を集約: z = sum(z_i)',
          '認可コードとなる認証アサーション (30秒有効, aud=gateway) が完成しました',
        ]
      : []
  );
  const [isCopied, setIsCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'visualizer' | 'jwt' | 'logs'>(initialTab);
  const [error, setError] = useState<string | null>(null);
  // `?step=completed` / `?step=jwt` paints a canned token for screenshots. Cleared the
  // moment a real sign-on starts, and labelled on screen so it is never mistaken for one.
  const [isMockView, setIsMockView] = useState(initialStep === 'completed');

  const [nodes, setNodes] = useState<NodeStatus[]>([
    { id: 1, name: 'ノード 1 (東京)', region: 'ap-northeast-1', state: initialStep === 'completed' ? 'success' : 'idle' },
    { id: 2, name: 'ノード 2 (フランクフルト)', region: 'eu-central-1', state: initialStep === 'completed' ? 'success' : 'idle' },
    { id: 3, name: 'ノード 3 (オレゴン)', region: 'us-west-2', state: initialStep === 'completed' ? 'success' : 'idle' },
  ]);

  const addLog = (msg: string) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  /**
   * Demo log sink (docs/container-split.md section 10, "browser" column). The SDK emits
   * one line per protocol step -- sign-on is three lines (blind, response, aggregate) -- and they go to
   * the log tab and to `console.log` verbatim, so the browser column can be read next to
   * the node and gateway terminals. No secret ever reaches a line: the SDK cuts every
   * per-session value to 8 characters and never passes the password, `h` or `h_i`.
   */
  const handleDemoEvent = (event: DemoEvent) => {
    for (const line of event.lines) {
      console.log(line);
    }
    setLogs((prev) => [...prev, ...event.lines]);

    if (event.step === 'signon-response') {
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'encrypted' })));
    } else if (event.step === 'signon-aggregate') {
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'success' })));
    } else if (event.kind === 'reject') {
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'idle' })));
    }
  };

  /**
   * A wrong password fails at the AEAD tag inside this browser, never at a node. Say so.
   */
  const describeFailure = (err: unknown): string => {
    const message = err instanceof Error ? err.message : String(err);
    if (/decrypt/i.test(message)) {
      return (
        '暗号文 ct_i の復号に失敗しました。パスワードが違います。' +
        'ノードは成否を知りません — 認証の成否はこの端末の中だけで決まります。'
      );
    }
    return `サインオンに失敗しました: ${message}`;
  };

  /**
   * Send the finished assertion back to the rp as the OAuth authorization code
   * (docs/container-split.md section 14.1, step 7): a plain GET redirect to
   * `redirect_uri?code=<assertion>&state=<state>`. The gateway and nodes are not on this
   * path; the rp's callback page exchanges the code at `/token` next.
   */
  const redirectToRpWithCode = (code: string) => {
    if (!oauthRedirectUri) return;
    const sep = oauthRedirectUri.includes('?') ? '&' : '?';
    const url =
      `${oauthRedirectUri}${sep}code=${encodeURIComponent(code)}` +
      `&state=${encodeURIComponent(oauthState)}`;
    window.location.href = url;
  };

  const startSignOn = async () => {
    if (!flowReady) {
      setError(MISSING_FLOW_MESSAGE);
      return;
    }

    setStep('signing');
    setLogs([]);
    setError(null);
    setIsMockView(false);
    setAssertion(null);
    setDecodedToken(null);
    addLog('分散サインオン処理を開始します (PASTA + FROST)...');

    // The page is served by the gateway itself, so an empty proxyUrl means same origin
    // and window.location.origin is the ISSUER the assertion is signed under (its aud too).
    const client = new DecentralizedClientSdk(
      {
        proxyUrl: '',
        issuer: window.location.origin,
        onEvent: handleDemoEvent,
      },
      oauthDpopJkt as string
    );
    addLog(`rp フロントから受け取った DPoP サムプリントに束縛します: cnf.jkt = ${client.cnfJkt}`);
    addLog('この画面は DPoP 秘密鍵を持ちません。鍵は rp オリジンの IndexedDB にあります。');
    addLog(`認可チャレンジ c = ${oauthChallenge} を認証アサーションの nonce に署名します。`);

    // 2. Client-side Password Blinding
    addLog('ブラウザ内でパスワードを目隠し暗号化: A = r * H1(pw) (Ristretto255群)...');
    addLog(`生のパスワード "${'*'.repeat(password.length)}" はネットワークに一度も流れません。`);
    await new Promise((r) => setTimeout(r, 900));

    // 3. Relay to distributed nodes
    setNodes((prev) => prev.map((n) => ({ ...n, state: 'sending' })));
    addLog('目隠しされた点 A を分散IdPの定足数ノード (t=2 / n=3) へ中継送信中...');
    await new Promise((r) => setTimeout(r, 900));
    setNodes((prev) => prev.map((n) => ({ ...n, state: 'evaluating' })));
    addLog('各ノードがパスワードを検証することなく 2HashTDH 部分評価値 B_i = k_i * A を計算中...');
    // Hold on the amber "評価中" state so the node animation is legible before the SDK
    // call (which then drives encrypted -> success through onEvent).
    await new Promise((r) => setTimeout(r, 800));

    try {
      const { assertion } = await client.signOn({
        username,
        password,
        clientId: oauthClientId,
        scope: oauthScope,
        nonce: oauthChallenge as string,
      });

      addLog('クライアント端末で暗号文 ct_i を復号成功（正しいパスワード所持の暗号学的証明）！');
      addLog('ラグランジュ補間係数を用いてFROST Schnorr署名を集約: z = sum(z_i)');
      addLog('認可コードとなる認証アサーション (30秒有効, aud=gateway) が完成しました！');
      addLog(`準備ができたら rp の ${oauthRedirectUri} へ code=<assertion> で戻ってください。`);

      setAssertion(assertion);
      setDecodedToken(decodeJwt(assertion));
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'success' })));
      setStep('completed');

      // Section 14.1 step 7: the code goes back to the rp only when the presenter presses
      // the button below -- no auto-redirect. A wrong password throws above and never
      // reaches the completed screen.
    } catch (err) {
      const message = describeFailure(err);
      addLog(message);
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'idle' })));
      setError(message);
      setStep('login');
    }
  };

  const copyToken = () => {
    if (assertion) {
      navigator.clipboard.writeText(assertion);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    }
  };

  const getNodeStateLabel = (state: NodeStatus['state']) => {
    switch (state) {
      case 'idle': return '待機中';
      case 'sending': return '送信中';
      case 'evaluating': return '部分評価中';
      case 'encrypted': return '暗号化完了';
      case 'success': return '結合完了';
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col justify-between">
      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-[#0d1322]/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-500/30">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-wide flex items-center gap-2">
              PASTA 分散型IdP
              <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full bg-indigo-900/60 text-indigo-300 border border-indigo-700/50 font-mono">
                FROST Ed25519
              </span>
            </h1>
            <p className="text-xs text-slate-400">ゼロ知識中継 OAuth 2.0 認可コードフロー (DPoP)</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="hidden sm:inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-violet-950/50 text-violet-300 border border-violet-700/50">
            <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-violet-400"></span>
            IdP · 分散認証基盤 · localhost:3000
          </span>
          <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
            <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            t = 2 / n = 3 定足数
          </span>
        </div>
      </header>

      {/* Cross-origin flow progress — this page is the IdP authentication stage. */}
      <div className="border-b border-slate-800 bg-[#0b1120]/60 px-4 py-4">
        <FlowStepper current={step === 'completed' ? 3 : 2} />
      </div>

      {/* Main Container */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-4 py-8 flex flex-col items-center justify-center">
        {step === 'login' && (
          <div className="w-full max-w-md glass-panel p-8 rounded-2xl cyber-glow">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-800">
              <div>
                <span className="text-xs text-indigo-400 font-semibold uppercase tracking-wider">連携アプリケーション認可</span>
                <h2 className="text-xl font-bold text-white mt-1">ZK-App Portal</h2>
              </div>
              <div className="w-10 h-10 rounded-xl bg-slate-800 flex items-center justify-center text-indigo-400 font-bold border border-slate-700 font-mono">
                ZK
              </div>
            </div>

            <div className="space-y-4">
              {error && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-200 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{error}</span>
                </div>
              )}

              {/* Section 13: no dpop_jkt means no key to bind the token to, so the flow
                  stops here rather than inventing one on this origin. */}
              {!flowReady && (
                <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/60 text-xs text-amber-200 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{MISSING_FLOW_MESSAGE}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">テストアカウント選択</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => { setUsername('alice'); setPassword('password123'); }}
                    className={`px-3 py-2 text-xs font-medium rounded-lg border transition ${
                      username === 'alice'
                        ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300'
                        : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:bg-slate-800'
                    }`}
                  >
                    Alice (一般ユーザー)
                  </button>
                  <button
                    type="button"
                    onClick={() => { setUsername('bob'); setPassword('password456'); }}
                    className={`px-3 py-2 text-xs font-medium rounded-lg border transition ${
                      username === 'bob'
                        ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300'
                        : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:bg-slate-800'
                    }`}
                  >
                    Bob (管理者)
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">ユーザー識別子 / ID</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900/90 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">マスターパスワード</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900/90 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition"
                />
              </div>

              <div className="p-3 rounded-lg bg-indigo-950/40 border border-indigo-800/40 text-xs text-indigo-300/90 space-y-1">
                <div className="font-semibold flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-indigo-400" />
                  PASTA 忘却型暗号化認証の保証
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  入力されたパスワードは<strong>サーバーへ送信されず、誰にも照合されません</strong>。端末内で目隠しされ、各ノードはパスワード由来の鍵で暗号化された署名シェアのみを返します。
                </p>
              </div>

              <button
                onClick={() => setStep('consent')}
                disabled={!flowReady}
                title={flowReady ? undefined : MISSING_FLOW_MESSAGE}
                className="w-full py-3 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:shadow-none text-white font-semibold text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30 mt-2"
              >
                権限の確認へ進む
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {step === 'consent' && (
          <div className="w-full max-w-md glass-panel p-8 rounded-2xl cyber-glow">
            <h2 className="text-lg font-bold text-white mb-2">認可とアクセス権限の確認</h2>
            <p className="text-xs text-slate-400 mb-6">
              <strong>ZK-App Portal</strong> は以下の暗号クレームの連携を要求しています:
            </p>

            <div className="space-y-3 mb-6">
              {[
                { id: 'openid', label: '認証アサーション (認可コード)', desc: 'FROST 定足数が署名した標準 EdDSA (Ed25519) JWT。30秒有効の OAuth 認可コード' },
                { id: 'profile', label: 'ユーザー固有識別子 (sub)', desc: '分散IdP環境で決定論的に決定される一意な識別子 (usr_alice_12345)' },
                { id: 'email', label: 'DPoP プルーフ束縛 (RFC 9449)', desc: 'rp フロントが生成した公開鍵へのトークン厳格束縛 (cnf.jkt = dpop_jkt)' },
              ].map((item) => (
                <div key={item.id} className="flex items-start gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-white">{item.label}</div>
                    <div className="text-[11px] text-slate-400">{item.desc}</div>
                  </div>
                </div>
              ))}
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setStep('login')}
                className="flex-1 py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition"
              >
                戻る
              </button>
              <button
                onClick={startSignOn}
                disabled={!flowReady}
                title={flowReady ? undefined : MISSING_FLOW_MESSAGE}
                className="flex-[2] py-2.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:shadow-none text-white font-semibold text-xs transition shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2"
              >
                <Key className="w-4 h-4" />
                認可してトークンを発行
              </button>
            </div>
          </div>
        )}

        {(step === 'signing' || step === 'completed') && (
          <div className="w-full max-w-4xl space-y-6">
            {isMockView && (
              <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-700/60 text-xs text-amber-200 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                <span className="leading-relaxed">
                  <strong>モック表示です。</strong>
                  この画面は <code className="font-mono">?step=completed</code> によるスクリーンショット用の固定値で、
                  実際のサインオンは行われていません。本物のトークンを見るにはログイン画面からやり直してください。
                </span>
              </div>
            )}

            {error && (
              <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-200 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                <span className="leading-relaxed">{error}</span>
              </div>
            )}

            {step === 'completed' && !isMockView && assertion && (
              <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-700/50 text-sm text-blue-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <span className="flex items-start gap-2 leading-relaxed">
                  <CheckCircle2 className="w-4 h-4 text-blue-300 flex-shrink-0 mt-0.5" />
                  認可コード (認証アサーション) が完成しました。準備ができたら連携先
                  <span className="font-semibold text-white"> RP · localhost:3001 </span>
                  へ戻ってください。
                </span>
                <button
                  onClick={() => redirectToRpWithCode(assertion)}
                  className="py-2.5 px-5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-blue-600/30 whitespace-nowrap"
                >
                  <ArrowRight className="w-4 h-4" />
                  連携先 RP へ戻る
                </button>
              </div>
            )}

            {/* Top Status Card */}
            <div className="glass-panel p-6 rounded-2xl cyber-glow">
              <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    {step === 'signing' ? (
                      <>
                        <RefreshCw className="w-5 h-5 text-indigo-400 animate-spin" />
                        分散サインオンプロトコルを実行中...
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                        認証成功 &amp; 署名集約完了！
                      </>
                    )}
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    2-of-3 しきい値定足数暗号処理 (PASTA 2HashTDH TOPRF + FROST 閾値Schnorr)
                  </p>
                </div>

                <div className="flex gap-2">
                  {(['visualizer', 'jwt', 'logs'] as const).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition ${
                        activeTab === tab
                          ? 'bg-indigo-600 border-indigo-500 text-white'
                          : 'bg-slate-800/60 border-slate-700 text-slate-400 hover:bg-slate-800'
                      }`}
                    >
                      {tab === 'visualizer' ? 'ノード通信可視化' : tab === 'jwt' ? '認証アサーション' : '処理ログ'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Tab 1: Visualizer */}
              {activeTab === 'visualizer' && (
                <div className="space-y-6">
                  <p className="text-[11px] text-slate-400 leading-relaxed flex items-start gap-2">
                    <Lock className="w-3.5 h-3.5 text-violet-400 flex-shrink-0 mt-0.5" />
                    各ノードはパスワードの正誤を検証しません。目隠しされた点を部分評価し、暗号化した署名シェアを返すだけです。認証の成否はこの端末の中でだけ決まります。
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {nodes.map((n) => (
                      <div
                        key={n.id}
                        className={`p-4 rounded-xl border transition-all ${
                          n.state === 'success'
                            ? 'bg-emerald-950/20 border-emerald-800/60'
                            : n.state !== 'idle'
                            ? 'bg-indigo-950/20 border-indigo-800/60'
                            : 'bg-slate-900/40 border-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Server className="w-4 h-4 text-slate-400" />
                            <span className="text-xs font-semibold text-white">{n.name}</span>
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono">{n.region}</span>
                        </div>

                        <div className="mt-3">
                          <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
                            <span>ノード状態</span>
                            <span className="font-mono text-indigo-400 text-[10px] font-semibold">
                              {getNodeStateLabel(n.state)}
                            </span>
                          </div>
                          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                            <div
                              className={`h-full transition-all duration-500 ${
                                n.state === 'success'
                                  ? 'w-full bg-emerald-500'
                                  : n.state === 'encrypted'
                                  ? 'w-3/4 bg-indigo-500'
                                  : n.state === 'evaluating'
                                  ? 'w-1/2 bg-amber-500 animate-pulse'
                                  : n.state === 'sending'
                                  ? 'w-1/4 bg-indigo-400 animate-pulse'
                                  : 'w-0'
                              }`}
                            ></div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Aggregator Node (User Browser) */}
                  <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
                        <Key className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white flex items-center gap-2">
                          ユーザー端末のブラウザ (集約者 / Aggregator)
                          <span className="text-[10px] px-2 py-0.2 rounded bg-indigo-900 text-indigo-300">
                            ゼロ知識保証
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400">
                          パスワード由来鍵で暗号文 ct_i を復号し、ラグランジュ補間により完全なEd25519署名を合成
                        </div>
                      </div>
                    </div>

                    {step === 'completed' && !isMockView && assertion && (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => redirectToRpWithCode(assertion)}
                          className="py-2 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition flex items-center gap-2 shadow-lg shadow-emerald-600/30"
                        >
                          <ArrowRight className="w-3.5 h-3.5" />
                          rp へ認可コードを渡して戻る
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab 2: JWT Viewer */}
              {activeTab === 'jwt' && assertion && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">認証アサーション (認可コード) — 標準 EdDSA JWT (RFC 8037, RFC 7519)</span>
                    <button
                      onClick={copyToken}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1.5 transition"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      {isCopied ? 'コピー完了！' : 'アサーションをコピー'}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950 font-mono text-xs break-all leading-relaxed border border-slate-800">
                    <span className="text-rose-400 font-semibold">{assertion.split('.')[0]}</span>
                    <span className="text-slate-600">.</span>
                    <span className="text-purple-400 font-semibold">{assertion.split('.')[1]}</span>
                    <span className="text-slate-600">.</span>
                    <span className="text-cyan-400 font-semibold">{assertion.split('.')[2]}</span>
                  </div>

                  {decodedToken && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                        <div className="text-[11px] text-rose-400 font-bold mb-1 font-mono">ヘッダー (Header): alg: EdDSA</div>
                        <pre className="text-[11px] text-slate-300 font-mono overflow-x-auto">
                          {JSON.stringify(decodedToken.header, null, 2)}
                        </pre>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                        <div className="text-[11px] text-purple-400 font-bold mb-1 font-mono">ペイロード (Payload): Claims &amp; cnf.jkt</div>
                        <pre className="text-[11px] text-slate-300 font-mono overflow-x-auto">
                          {JSON.stringify(decodedToken.payload, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Logs */}
              {activeTab === 'logs' && (
                <div className="p-4 rounded-xl bg-slate-950 font-mono text-xs border border-slate-800 max-h-72 overflow-y-auto space-y-1 text-slate-300">
                  {logs.map((log, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-indigo-500 font-bold">&gt;</span>
                      <span>{log}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Bottom Actions */}
            {step === 'completed' && (
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => {
                    setStep('login');
                    setError(null);
                    setIsMockView(false);
                    setNodes((prev) => prev.map((n) => ({ ...n, state: 'idle' })));
                  }}
                  className="py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition"
                >
                  別のアカウントでサインオンを試す
                </button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-4 px-6 text-center text-xs text-slate-500">
        PASTA (CCS 2018) + FROST (RFC 8032 Ed25519) 実装 &bull; RFC 9449 DPoP 束縛 &bull; OAuth 2.0 認可コード (認証アサーション)
      </footer>
    </div>
  );
}
