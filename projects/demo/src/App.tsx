import { useState } from 'react';
import { Shield, Key, Lock, CheckCircle2, RefreshCw, Send, ArrowRight, Server, Copy, AlertTriangle } from 'lucide-react';
import { DecentralizedClientSdk } from './sdk/client';
import type { DemoEvent } from './sdk/events';

interface NodeStatus {
  id: number;
  name: string;
  region: string;
  state: 'idle' | 'sending' | 'evaluating' | 'encrypted' | 'success';
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

  // OAuth フロー連携パラメータ — /rp → /authorize → /demo?redirect_uri=...
  const oauthRedirectUri = urlParams?.get('redirect_uri') || null;
  const oauthClientId = urlParams?.get('client_id') || 'zk_app_portal';
  const oauthNonce = urlParams?.get('nonce') || ('demo_nonce_' + Math.random().toString(36).substring(7));
  const oauthState = urlParams?.get('state') || 'demo_state_xyz789';

  const defaultMockToken =
    'eyJhbGciOiJFZERTQSIswitchInR5cCI6IkpXVCIsImtpZCI6InBhc3RhLWZyb3N0ZWQyNTUxOS1wazEifQ.eyJpc3MiOiJodHRwczovL2lkcC5wYXN0YS5leGFtcGxlIiwic3ViIjoidXNyX2FsaWNlXzEyMzQ1IiwiYXVkIjoiemtfYXBwX3BvcnRhbCIsImlhdCI6MTcyMTAxMDAwMCwiZXhwIjoxNzIxMDEzODAwLCJqdGkiOiJqdGlfZGVtb185OTkiLCJjbmYiOnsiamt0IjoiNmNQUU5JbWZiaHFtakh6NVhEOVU4MjZ1WllMNUtSNVNtOWJtM051UVhNIn19.dGVzdF9zaWduYXR1cmVfZm9yX2RlbW9fcGFzdGFfZm9yX3NjcmVlbnNob3Q';

  const [step, setStep] = useState<'login' | 'consent' | 'signing' | 'completed'>(initialStep);
  const [username, setUsername] = useState('alice');
  const [password, setPassword] = useState('password123');
  const [idToken, setIdToken] = useState<string | null>(initialStep === 'completed' ? defaultMockToken : null);
  const [decodedToken, setDecodedToken] = useState<any>(
    initialStep === 'completed'
      ? {
          header: { alg: 'EdDSA', typ: 'JWT', kid: 'pasta-frosted25519-pk1' },
          payload: {
            iss: 'https://idp.pasta.example',
            sub: 'usr_alice_12345',
            aud: 'zk_app_portal',
            iat: 1721010000,
            exp: 1721013800,
            jti: 'jti_demo_999',
            cnf: { jkt: '6cPQNImfbhqmjHz5XD9U826uZYL5KR5Sm9bm3NuQXM' },
          },
        }
      : null
  );
  const [logs, setLogs] = useState<string[]>(
    initialStep === 'completed'
      ? [
          '分散サインオン処理を開始します (PASTA + FROST)...',
          '端末内でRFC 9449 DPoP用の一時Ed25519キーペアを生成中...',
          'DPoP公開鍵サムプリント算出完了: cnf.jkt = 6cPQNImfbhqmjHz5XD9U826uZYL5KR5Sm9bm3NuQXM',
          'ブラウザ内でパスワードを目隠し暗号化: A = r * H1(pw) (Ristretto255群)...',
          '各ノードがパスワードを検証することなく 2HashTDH 部分評価値 B_i を計算完了',
          '各ノードがFROST署名シェア z_i を生成し、h_i で暗号化完了',
          'クライアント端末で暗号文 ct_i を復号成功（正しいパスワード所持の暗号学的証明）',
          'ラグランジュ補間係数を用いてFROST Schnorr署名を集約: z = sum(z_i)',
          '標準Ed25519公開鍵で検証可能なIDトークンが完成しました',
        ]
      : []
  );
  const [isCopied, setIsCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'visualizer' | 'jwt' | 'logs'>(initialTab);
  const [error, setError] = useState<string | null>(null);
  // `?step=completed` / `?step=jwt` paints a canned token for screenshots. Cleared the
  // moment a real sign-on starts, and labelled on screen so it is never mistaken for one.
  const [isMockView, setIsMockView] = useState(initialStep === 'completed');
  const [sdk, setSdk] = useState<DecentralizedClientSdk | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

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
   * one line per protocol step -- sign-on is three lines, refresh is one -- and they go to
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

  const startSignOn = async () => {
    setStep('signing');
    setLogs([]);
    setError(null);
    setIsMockView(false);
    setIdToken(null);
    setDecodedToken(null);
    setSdk(null);
    addLog('分散サインオン処理を開始します (PASTA + FROST)...');

    // 1. Client-side ephemeral DPoP Key Generation (Hole 4 & 7)
    addLog('端末内でRFC 9449 DPoP用の一時Ed25519キーペアを生成中...');
    await new Promise((r) => setTimeout(r, 400));

    // The page is served by the gateway itself, so an empty proxyUrl means same origin
    // and window.location.origin is the ISSUER the gateway signs with.
    const client = new DecentralizedClientSdk({
      proxyUrl: '',
      issuer: window.location.origin,
      onEvent: handleDemoEvent,
    });
    addLog(`DPoP公開鍵サムプリント算出完了: cnf.jkt = ${client.cnfJkt}`);

    // 2. Client-side Password Blinding
    addLog('ブラウザ内でパスワードを目隠し暗号化: A = r * H1(pw) (Ristretto255群)...');
    addLog(`生のパスワード "${'*'.repeat(password.length)}" はネットワークに一度も流れません。`);
    await new Promise((r) => setTimeout(r, 300));

    // 3. Relay to distributed nodes
    setNodes((prev) => prev.map((n) => ({ ...n, state: 'sending' })));
    addLog('目隠しされた点 A を分散IdPの定足数ノード (t=2 / n=3) へ中継送信中...');
    await new Promise((r) => setTimeout(r, 300));
    setNodes((prev) => prev.map((n) => ({ ...n, state: 'evaluating' })));
    addLog('各ノードがパスワードを検証することなく 2HashTDH 部分評価値 B_i = k_i * A を計算中...');

    try {
      const { id_token } = await client.signOn({
        username,
        password,
        clientId: oauthClientId,
        nonce: oauthNonce,
      });

      addLog('クライアント端末で暗号文 ct_i を復号成功（正しいパスワード所持の暗号学的証明）！');
      addLog('ラグランジュ補間係数を用いてFROST Schnorr署名を集約: z = sum(z_i)');
      addLog('標準Ed25519公開鍵で検証可能なIDトークンが完成しました！');

      setSdk(client);
      setIdToken(id_token);
      setDecodedToken(decodeJwt(id_token));
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'success' })));
      setStep('completed');
    } catch (err) {
      const message = describeFailure(err);
      addLog(message);
      setNodes((prev) => prev.map((n) => ({ ...n, state: 'idle' })));
      setError(message);
      setStep('login');
    }
  };

  const runRefresh = async () => {
    if (!sdk) return;
    setIsRefreshing(true);
    setError(null);
    addLog('DPoP proof を作成し、同じ参加ノード集合へリフレッシュを要求します...');
    try {
      const { id_token } = await sdk.refresh({
        clientId: oauthClientId,
        nonce: oauthNonce,
        refreshEndpointUrl: `${window.location.origin}/api/pasta/refresh`,
      });
      addLog('新しい ct_i を rk_i = HKDF(rs_i, ctr) で復号し、新しい id_token を集約しました。');
      setIdToken(id_token);
      setDecodedToken(decodeJwt(id_token));
      setActiveTab('jwt');
    } catch (err) {
      const message =
        err instanceof Error ? `リフレッシュに失敗しました: ${err.message}` : String(err);
      addLog(message);
      setError(message);
    } finally {
      setIsRefreshing(false);
    }
  };

  const copyToken = () => {
    if (idToken) {
      navigator.clipboard.writeText(idToken);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    }
  };

  const submitFormPostToRp = () => {
    if (!idToken) return;
    const targetUri = oauthRedirectUri || 'http://localhost:3000/demo/rp-callback';
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = targetUri;
    form.target = oauthRedirectUri ? '_self' : '_blank';

    const tokenInput = document.createElement('input');
    tokenInput.type = 'hidden';
    tokenInput.name = 'id_token';
    tokenInput.value = idToken;
    form.appendChild(tokenInput);

    const stateInput = document.createElement('input');
    stateInput.type = 'hidden';
    stateInput.name = 'state';
    stateInput.value = oauthState;
    form.appendChild(stateInput);

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
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
            <p className="text-xs text-slate-400">ゼロ知識中継 OAuth 2.0 / OpenID Connect アーキテクチャ</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
            <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            t = 2 / n = 3 定足数 正常稼働中
          </span>
        </div>
      </header>

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
                className="w-full py-3 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30 mt-2"
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
                { id: 'openid', label: 'OpenID プロファイル', desc: 'FROST 定足数によって署名された標準 EdDSA (Ed25519) JWT IDトークン' },
                { id: 'profile', label: 'ユーザー固有識別子 (sub)', desc: '分散IdP環境で決定論的に決定される一意な識別子 (usr_alice_12345)' },
                { id: 'email', label: 'DPoP プルーフ束縛 (RFC 9449)', desc: 'ブラウザ内で生成された使い捨て公開鍵へのトークン厳格束縛 (cnf.jkt)' },
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
                className="flex-[2] py-2.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2"
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
                      {tab === 'visualizer' ? 'ノード通信可視化' : tab === 'jwt' ? 'JWT トークン検証' : '処理ログ'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Tab 1: Visualizer */}
              {activeTab === 'visualizer' && (
                <div className="space-y-6">
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

                    {step === 'completed' && (
                      <div className="flex items-center gap-2">
                        {sdk && (
                          <button
                            onClick={runRefresh}
                            disabled={isRefreshing}
                            className="py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 font-semibold text-xs transition flex items-center gap-2 border border-slate-700"
                          >
                            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                            {isRefreshing ? 'リフレッシュ中...' : 'DPoP リフレッシュ'}
                          </button>
                        )}
                        <button
                          onClick={submitFormPostToRp}
                          className="py-2 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition flex items-center gap-2 shadow-lg shadow-emerald-600/30"
                        >
                          <Send className="w-3.5 h-3.5" />
                          RPへ form_post で直接送信
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab 2: JWT Viewer */}
              {activeTab === 'jwt' && idToken && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">標準 RFC 7519 JWT (アルゴリズム: EdDSA, RFC 8037)</span>
                    <button
                      onClick={copyToken}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1.5 transition"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      {isCopied ? 'コピー完了！' : 'JWTをコピー'}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950 font-mono text-xs break-all leading-relaxed border border-slate-800">
                    <span className="text-rose-400 font-semibold">{idToken.split('.')[0]}</span>
                    <span className="text-slate-600">.</span>
                    <span className="text-purple-400 font-semibold">{idToken.split('.')[1]}</span>
                    <span className="text-slate-600">.</span>
                    <span className="text-cyan-400 font-semibold">{idToken.split('.')[2]}</span>
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
        PASTA (CCS 2018) + FROST (RFC 8032 Ed25519) 実装 &bull; RFC 9449 DPoP 一時鍵束縛 &bull; response_mode=form_post
      </footer>
    </div>
  );
}
