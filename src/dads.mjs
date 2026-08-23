// デジタル庁デザインシステム（DADS）β v2.17.1 の基盤層。
//
// **値の出所は公式 npm パッケージ**（推測で書かない）:
//   @digital-go-jp/design-tokens@2.0.1        … dist/tokens.css（プリミティブ/セマンティック/角丸/字面）
//   @digital-go-jp/tailwind-theme-plugin@1.0.1 … dist/index.es.js（型スケールの weight/lh/tracking、focus 色、breakpoint）
// Figma（community 1377880368787735577）は開けないので参照していない。
// **トークンのバージョンとデザインシステムのバージョンは別**（DS は v2.17.1 / tokens は v2.0.1）。
//
// ここに置くのは「DADS が決めていること」だけ。**アプリ固有の判断は置かない**
// （役割色の割り当ては ROLE_THEME に分け、なぜその色かを個別に書く）。
//
// 守るべき規定で、実装が破りやすいもの3つ:
//  1. **本文・UI は 16px 以上**（`基本的にフォントサイズは16 CSS px以上で使用します`）。
//     14px はフッター等の制約下のみ、14px 未満は不可。**現行 UI は 12px が98箇所・11px が80箇所**
//     あり、刷新の主作業はここ（色ではない）
//  2. **フォーカスインジケーターは Yellow-300 + Black の二重で、いかなる場合も変更してはいけない**
//     （`--dads-focus-ring`）。役割色でフォーカスを描いてはいけない
//  3. **ウェイトは 400 と 700 だけ**。500/600 は DADS に存在しない

/** 型スケール。名前は DADS の呼称（Dsp/Std/Dns/Oln/Mono + サイズ + B|N + 行間%）。 */
export const TYPE = {
  'std-32B-150': ['2rem', 700, 1.5, '0.01em'],
  'std-28B-150': ['1.75rem', 700, 1.5, '0.01em'],
  'std-24B-150': ['1.5rem', 700, 1.5, '0.02em'],
  'std-22B-150': ['1.375rem', 700, 1.5, '0.02em'],
  'std-20B-160': ['1.25rem', 700, 1.6, '0.02em'],
  'std-18B-160': ['1.125rem', 700, 1.6, '0.02em'],
  'std-17B-170': ['1.0625rem', 700, 1.7, '0.02em'],
  'std-16B-170': ['1rem', 700, 1.7, '0.02em'],
  'std-17N-170': ['1.0625rem', 400, 1.7, '0.02em'],
  'std-16N-170': ['1rem', 400, 1.7, '0.02em'],
  'std-16N-175': ['1rem', 400, 1.75, '0.02em'],
  'dns-17B-130': ['1.0625rem', 700, 1.3, '0'],
  'dns-16B-130': ['1rem', 700, 1.3, '0'],
  'dns-16N-130': ['1rem', 400, 1.3, '0'],
  'dns-14B-130': ['0.875rem', 700, 1.3, '0'],
  'dns-14N-130': ['0.875rem', 400, 1.3, '0'],
  'oln-16B-100': ['1rem', 700, 1, '0.02em'],
  'oln-16N-100': ['1rem', 400, 1, '0.02em'],
  'oln-14B-100': ['0.875rem', 700, 1, '0.02em'],
  'oln-14N-100': ['0.875rem', 400, 1, '0.02em'],
  'mono-16N-150': ['1rem', 400, 1.5, '0'],
  'mono-14N-150': ['0.875rem', 400, 1.5, '0'],
};

/** 型スケール1件を CSS 宣言へ。`font: inherit` を上書きする場面で使う。 */
export const type = (name) => {
  const t = TYPE[name];
  if (!t) throw new Error(`unknown DADS type style: ${name}`);
  return `font-size:${t[0]};font-weight:${t[1]};line-height:${t[2]};letter-spacing:${t[3]}`;
};

/**
 * 役割色（本デモ固有の判断。DADS の規定ではない）。
 *
 * 3つのオリジンが別々の主体であることを示すのは本デモの中核なので、色分けは残す。
 * ただし**割り当ては DADS のプリミティブから選び直す**。理由が色ごとに違う:
 *  - issuer=**key(青)**: DADS の主要色そのもの。発行者は行政窓口の顔なので既定色でよい
 *  - verifier=**magenta**: 現行は煉瓦色だったが、**DADS では red がエラーの意味に予約されている**
 *    （`--color-semantic-error-1/2` = red-800/900）。赤いヘッダーは「異常が起きている」と読める
 *  - wallet=**cyan**: 現行のティールに最も近い。**green は success に予約**されているので使えない
 *  - admin=**purple**: 江戸紫の後継。上記3つのどれとも色相が離れている
 *
 * **アクション（主ボタン・リンク）は役割色でなく常に key(青)** にする。DADS はボタンの色で
 * 優先度を示す設計で、色そのものに「操作できる」という意味を持たせている。役割色で塗ると
 * サイトごとに「押せる色」が変わってしまう。役割色はヘッダー帯と識別チップに限定する。
 */
export const ROLE_THEME = {
  issuer:   { ink: '#0017c1', tint: '#e8f1fe', line: '#c5d7fb' }, // key-900 / key-50 / key-200
  verifier: { ink: '#8b008b', tint: '#f3e5f4', line: '#ffaeff' }, // magenta-900 / -50 / -200
  wallet:   { ink: '#006173', tint: '#e9f7f9', line: '#99f2ff' }, // cyan-1000 / -50 / -200
  admin:    { ink: '#41048e', tint: '#f1eafa', line: '#ddc2ff' }, // purple-1000 / -50 / -200
};

/** Google Fonts。DADS の指定は Noto Sans JP / Noto Sans Mono、ウェイトは 400 と 700 のみ。 */
export const DADS_FONTS =
  '<link rel="preconnect" href="https://fonts.googleapis.com">' +
  '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
  '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?' +
  'family=Noto+Sans+JP:wght@400;700&family=Noto+Sans+Mono:wght@400;700&display=swap">';

/** トークン層。プリミティブは使うものだけ写し、意味のある名前は別に張る。 */
export const DADS_TOKENS = `
  :root{
    /* --- primitive（@digital-go-jp/design-tokens@2.0.1 より） --- */
    --key-50:#e8f1fe;--key-100:#d9e6ff;--key-200:#c5d7fb;--key-700:#264af4;
    --key-800:#0031d8;--key-900:#0017c1;--key-1000:#00118f;--key-1100:#000071;
    --gray-50:#f2f2f2;--gray-100:#e6e6e6;--gray-200:#cccccc;--gray-300:#b3b3b3;
    --gray-420:#949494;--gray-536:#767676;--gray-600:#666666;--gray-700:#4d4d4d;
    --gray-800:#333333;--gray-900:#1a1a1a;
    --yellow-300:#ffd43d;
    /* --- semantic（同パッケージの --color-semantic-*） --- */
    --success-1:#259d63;--success-2:#197a4b;
    --error-1:#ec0000;--error-2:#ce0000;
    --warning-1:#b78f00;--warning-2:#927200;
    --focus-yellow:#b78f00;--focus-blue:#0877d7;
    /* --- 用途名（本デモが張る別名。地の色と文字色） --- */
    --ink:var(--gray-900);            /* 本文 */
    --ink-sub:var(--gray-700);        /* 補助文（gray-536 が AA 下限なので 700 を既定に） */
    --line:var(--gray-200);
    --surface:#ffffff;
    --paper:var(--gray-50);
    /* --- 角丸・影（トークンそのまま） --- */
    --r4:.25rem;--r6:.375rem;--r8:.5rem;--r12:.75rem;--r16:1rem;--r24:1.5rem;--r-full:624.9375rem;
    --e1:0 2px 8px 1px rgba(0,0,0,.1),0 1px 5px 0 rgba(0,0,0,.3);
    --e2:0 2px 12px 2px rgba(0,0,0,.1),0 1px 6px 0 rgba(0,0,0,.3);
    --e3:0 4px 16px 3px rgba(0,0,0,.1),0 1px 6px 0 rgba(0,0,0,.3);
    /* --- 余白（8px 基準。DADS は 3〜5段を推奨し、例として 8/24/64 を挙げる） --- */
    --sp1:8px;--sp2:16px;--sp3:24px;--sp5:40px;--sp8:64px;
    /* --- 役割色（既定=issuer） --- */
    --role-ink:#0017c1;--role-tint:#e8f1fe;--role-line:#c5d7fb;
    /* 他サイトの役割色を名指しするための別名。**他の主体を指すとき**に使う——
       ウォレットの提示同意で相手（検証者）を表す、開発者コンソールで発行者宛の通信を
       色分けする、など。--role-ink は「いま自分がいるサイト」なので流用できない。 */
    --ink-issuer:#0017c1;--ink-verifier:#8b008b;--ink-wallet:#006173;--ink-admin:#41048e;
  }
  body.role-issuer  {--role-ink:#0017c1;--role-tint:#e8f1fe;--role-line:#c5d7fb}
  body.role-verifier{--role-ink:#8b008b;--role-tint:#f3e5f4;--role-line:#ffaeff}
  body.role-wallet  {--role-ink:#006173;--role-tint:#e9f7f9;--role-line:#99f2ff}
  body.role-admin   {--role-ink:#41048e;--role-tint:#f1eafa;--role-line:#ddc2ff}
`;

/**
 * 基本要素。**フォーカスリングは1箇所で定義して全部から参照する**
 * （Yellow-300 と Black の二重構造・変更禁止。個別に outline を書かせない）。
 */
export const DADS_BASE = `
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0;background:var(--paper);color:var(--ink);
    font-family:'Noto Sans JP',-apple-system,BlinkMacSystemFont,sans-serif;
    ${type('std-16N-170')}}
  .mono{font-family:'Noto Sans Mono',monospace;${type('mono-14N-150')}}
  /* フォーカス: Yellow-300 の内側リング + Black の外側リング。DADS「いかなる場合も変更してはいけない」 */
  :where(a,button,input,select,textarea,summary,[tabindex]):focus-visible{
    outline:2px solid var(--yellow-300);outline-offset:0;
    box-shadow:0 0 0 2px #000,0 0 0 4px var(--yellow-300);border-radius:var(--r4)}
  h1{${type('std-32B-150')};margin:0 0 var(--sp3)}
  h2{${type('std-24B-150')};margin:var(--sp5) 0 var(--sp2)}
  h3{${type('std-20B-160')};margin:var(--sp3) 0 var(--sp1)}
  p{margin:0 0 var(--sp2)}
  a{color:var(--key-900);text-underline-offset:.2em}
  a:hover{color:var(--key-1000)}
  small{${type('dns-14N-130')}}
`;

/**
 * ボタン。DADS の最小寸法は L=136×56 / M=96×48 / S=80×36 / XS=72×28 で、
 * **ターゲット領域は 44px 以上**（S/XS は上下に余白を足して確保する）。
 * 種類は塗り／輪郭／テキストの3つ。**主ボタンは1画面に1つ**。
 */
export const DADS_BUTTON = `
  .dbtn{display:inline-flex;align-items:center;justify-content:center;gap:var(--sp1);
    min-width:96px;min-height:48px;padding:0 var(--sp3);border-radius:var(--r8);
    ${type('oln-16B-100')};text-decoration:none;cursor:pointer;border:2px solid transparent;
    transition:background-color .12s ease,color .12s ease,border-color .12s ease}
  .dbtn-lg{min-width:136px;min-height:56px}
  /* S/XS は見た目の高さを下げつつ、当たり判定は 44px を保つ */
  .dbtn-sm{min-width:80px;min-height:36px;padding:0 var(--sp2);${type('oln-14B-100')};
    position:relative}
  .dbtn-sm::after{content:"";position:absolute;left:0;right:0;top:50%;height:44px;transform:translateY(-50%)}
  /* 塗り = 主ボタン。色は役割色でなく key（押せる色をサイトごとに変えない） */
  .dbtn-fill{background:var(--key-900);color:#fff}
  .dbtn-fill:hover{background:var(--key-1000);color:#fff}
  .dbtn-fill:active{background:var(--key-1100)}
  /* 輪郭 = 副ボタン */
  .dbtn-out{background:#fff;color:var(--key-900);border-color:var(--key-900)}
  .dbtn-out:hover{background:var(--key-50)}
  /* テキスト = 取消・戻る */
  .dbtn-text{background:transparent;color:var(--key-900);text-decoration:underline;
    min-width:0;padding:0 var(--sp1)}
  .dbtn-text:hover{background:var(--key-50)}
  .dbtn[aria-disabled=true],.dbtn:disabled{background:var(--gray-200);color:var(--gray-600);
    border-color:transparent;cursor:not-allowed}
  /* 並び順: 右=前進/完了、左=戻る/取消 */
  .dbtn-row{display:flex;gap:var(--sp2);align-items:center;flex-wrap:wrap}
  .dbtn-row.end{justify-content:flex-end}
`;

/** 入力欄・ラベル・エラー。ラベルは常に可視（プレースホルダで代替しない）。 */
export const DADS_FORM = `
  .dfield{display:block;margin-bottom:var(--sp3)}
  .dlabel{display:block;${type('std-16B-170')};margin-bottom:var(--sp1)}
  .dlabel .req{color:var(--error-2);margin-left:.4em;${type('dns-14B-130')}}
  .dhelp{display:block;${type('dns-14N-130')};color:var(--ink-sub);margin-bottom:var(--sp1)}
  .dinput,.dselect,.dtextarea{display:block;width:100%;min-height:48px;padding:10px 12px;
    ${type('std-16N-170')};font-family:inherit;color:var(--ink);
    background:#fff;border:2px solid var(--gray-700);border-radius:var(--r8)}
  .dtextarea{min-height:120px;resize:vertical}
  .dinput::placeholder{color:var(--gray-536)}
  .dfield.err .dinput,.dfield.err .dselect,.dfield.err .dtextarea{border-color:var(--error-2)}
  .derr{display:block;${type('dns-14B-130')};color:var(--error-2);margin-top:var(--sp1)}
  /* ラジオ/チェックは 24px の実寸を持たせ、行全体を 44px の当たり判定にする */
  .dcheck{display:flex;align-items:center;gap:12px;min-height:44px;${type('std-16N-170')}}
  .dcheck input{width:24px;height:24px;margin:0;accent-color:var(--key-900);flex:none}
`;

/** 注釈ブロック・チップ。意味色（成功/エラー/警告）はここでしか使わない。 */
export const DADS_NOTICE = `
  .dnotice{border-left:4px solid var(--key-900);background:var(--key-50);
    padding:var(--sp2);border-radius:0 var(--r8) var(--r8) 0;margin:var(--sp2) 0;
    ${type('std-16N-170')}}
  .dnotice.warn{border-color:var(--warning-1);background:#fbf5e0}
  .dnotice.err{border-color:var(--error-2);background:#fdeeee}
  .dnotice.ok{border-color:var(--success-2);background:#e6f5ec}
  .dnotice b{display:block;${type('std-16B-170')};margin-bottom:4px}
  /* チップラベル = 状態の表示（押せない）。DADS のチップは 14px を下回らない */
  .dchip{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;
    border-radius:var(--r-full);${type('dns-14B-130')};border:1px solid var(--gray-200);
    background:#fff;color:var(--ink-sub);white-space:nowrap}
  .dchip.ok{color:var(--success-2);border-color:#9bd4b5;background:#e6f5ec}
  .dchip.err{color:var(--error-2);border-color:#ffbbbb;background:#fdeeee}
  .dchip.warn{color:var(--warning-2);border-color:#ffe380;background:#fbf5e0}
  .dchip.role{color:var(--role-ink);border-color:var(--role-line);background:var(--role-tint)}
`;

/** ステップナビゲーション（申請・シナリオの進行表示）。 */
export const DADS_STEPS = `
  .dsteps{display:flex;flex-wrap:wrap;gap:var(--sp1);list-style:none;padding:0;margin:0 0 var(--sp3)}
  .dstep{display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:var(--r-full);
    ${type('dns-14B-130')};background:#fff;border:1px solid var(--line);color:var(--ink-sub)}
  .dstep .n{display:grid;place-items:center;width:24px;height:24px;border-radius:var(--r-full);
    background:var(--gray-100);color:var(--ink-sub);${type('dns-14B-130')};flex:none}
  .dstep.cur{border-color:var(--key-900);color:var(--key-900);background:var(--key-50)}
  .dstep.cur .n{background:var(--key-900);color:#fff}
  .dstep.done{color:var(--success-2);border-color:#9bd4b5;background:#e6f5ec}
  .dstep.done .n{background:var(--success-2);color:#fff}
`;

/**
 * **ドラフト用の上書き層**。既存クラス（`.card` `.btn` `.top` …）を DADS の値へ写す。
 *
 * これは最終形ではない——本採用が決まったら画面ごとにマークアップを DADS の
 * コンポーネント（`.dbtn` `.dfield` `.dchip` …）へ書き換え、この層は捨てる。
 * 先に上書きで当てるのは、**方向性の確認に必要なのは実画面であってモックではない**ため。
 *
 * 効き方の大半は色でなく**字面**（16px 下限）。既存 CSS は 12px が98箇所・11px が80箇所あり、
 * それを個別に直すと差分が読めなくなるので、ここでまとめて底上げしてから個別調整に入る。
 */
const DADS_OVERRIDE_SRC = `
  body{font-family:'Noto Sans JP',-apple-system,BlinkMacSystemFont,sans-serif;
    ${type('std-16N-170')};background:var(--paper);color:var(--ink)}
  .mono,.urlbox,code{font-family:'Noto Sans Mono',monospace}
  /* --- 16px 下限。14px は補助情報のみ（DADS: 14px 未満は不可） --- */
  .hint,.nm,.req,.step,.urlbox,table.cl,.ok,.cnote,.wli-note,.vcs-note,.wd-note{
    ${type('std-16N-170')}}
  .req .k,.top small{${type('std-16N-170')};color:var(--ink-sub);letter-spacing:0}
  .eyebrow{${type('oln-16B-100')};color:var(--role-ink);letter-spacing:.14em}
  h1{${type('std-24B-150')};margin:.2rem 0 var(--sp3)}
  /* --- ヘッダー: 役割の色は帯と識別チップに限定する --- */
  .top{background:var(--role-tint);border-bottom:1px solid var(--role-line);padding:14px 24px}
  .top .tag,.top.verifier .tag,.top.wallet .tag{background:var(--role-ink);border-radius:var(--r4)}
  .top b{${type('std-17B-170')}}
  .top .role,.top.issuer .role,.top.verifier .role,.top.wallet .role{
    ${type('dns-14B-130')};color:var(--role-ink);background:#fff;
    border:1px solid var(--role-line);border-radius:var(--r-full);padding:6px 14px}
  .demoband{${type('dns-14N-130')};color:#6e5600;background:#fbf5e0;
    border-bottom:1px solid #ffe380;padding:6px 24px;letter-spacing:0}
  /* --- 面 --- */
  .card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r12);padding:var(--sp3)}
  .req,.urlbox{background:var(--gray-50);border:1px solid var(--line);border-radius:var(--r8);padding:var(--sp2)}
  .req b{color:var(--ink);font-weight:700}
  table.cl td{padding:10px 8px;border-bottom:1px solid var(--line)}
  table.cl td:first-child{color:var(--ink-sub)}
  .userbtn{border:1px solid var(--line);border-radius:var(--r12);padding:var(--sp2) 10px}
  .userbtn:hover{border-color:var(--gray-300);box-shadow:var(--e1);transform:none}
  /* --- ボタン: 押せる色はサイト共通で key(青)。高さ 48px・文字 16px --- */
  a.btn,button.btn{background:var(--key-900);color:#fff;border:2px solid transparent;
    border-radius:var(--r8);min-height:48px;min-width:96px;padding:0 var(--sp3);
    display:inline-flex;align-items:center;justify-content:center;${type('oln-16B-100')}}
  a.btn:hover,button.btn:hover{background:var(--key-1000)}
  /* --- 状態の色は意味色に寄せる（成功=green / 失効=red / 未確認=gray） --- */
  .ok{color:var(--success-2);${type('dns-14B-130')}}
  /* --- フォーカス: Yellow-300 + Black の二重。役割色で描かない（DADS 変更禁止） --- */
  .brandlink:focus-visible,a:focus-visible,button:focus-visible,
  input:focus-visible,select:focus-visible,textarea:focus-visible,summary:focus-visible{
    outline:2px solid var(--yellow-300);outline-offset:0;
    box-shadow:0 0 0 2px #000,0 0 0 4px var(--yellow-300)}
  /* --- 入力: 高さ 48px・枠 2px・文字 16px（iOS の自動ズーム回避も兼ねる） --- */
  input[type=text],input[type=tel],input[type=date],input[type=email],input[type=password],select,textarea{
    min-height:48px;padding:10px 12px;${type('std-16N-170')};font-family:inherit;
    border:2px solid var(--gray-700);border-radius:var(--r8);background:#fff;color:var(--ink)}
  textarea{min-height:120px}
  input[type=radio],input[type=checkbox]{width:24px;height:24px;accent-color:var(--key-900)}
  /* --- タップ領域 44px（DADS「ボタンのターゲット領域は44 CSS px以上を保ってください」） ---
     見た目の高さは変えずに当たり判定だけ広げる。行が縦に密な場所では隣と重なるので、
     **横一列に並ぶチップ類にだけ**適用する。 */
  .vcs-chip,.seg3 button,.seg button,.mini,.wchip,.fmtb{min-height:44px}
  /* 円形の小さなアイコンボタンは寸法を変えられないので疑似要素で当たり判定を広げる */
  .vcinfo,.dev-toggle{position:relative}
  .vcinfo::after,.dev-toggle::after{content:"";position:absolute;left:50%;top:50%;
    width:44px;height:44px;transform:translate(-50%,-50%)}
`;

/**
 * **CSS コメントは配信前に落とす**（2026-08-23 にテストが捕まえた）。
 * この CSS はインラインで `<style>` に埋まるので、**コメント内の日本語がそのまま HTML の
 * バイト列に載る**。`/* 状態の色…未確認=gray *​/` と書いたせいで、ウォレットのホームに
 * 「未確認」の文字が無いことを見るテストが落ちた——画面には出ないのに本文としては存在する、
 * という気づきにくい形。語を避けて書くのは破綻するので、**構造的に落とす**。
 * 転送量も減る（コメントは説明でありレスポンスの一部ではない）。
 */
const stripComments = (css) => css.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\n{2,}/g, '\n');

/** 全部まとめて1つの `<style>` に入れるための束。 */
export const DADS_CSS = stripComments(
  DADS_TOKENS + DADS_BASE + DADS_BUTTON + DADS_FORM + DADS_NOTICE + DADS_STEPS);

export const DADS_OVERRIDE = stripComments(DADS_OVERRIDE_SRC);
