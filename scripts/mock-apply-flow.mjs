// 申請ベース発行の画面モック（実装前の合意用）。案E 確定を前提に、
// 申請 → 受付 → 審査（被害認定）→ 認定 → 交付、および再判定→失効までを描く。
// 汎用性の確認のため罹災（自由記述+写真）と離島（区分+必要書類）の2種を出す。
// 使い方: node scripts/mock-apply-flow.mjs → web/captures/mock-flow-*.png
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WALLET_CARD_THEME, swatchEmblemHtml, swatchEmblemCss } from '../src/authcode-demo.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const sw = (type) => {
  const t = WALLET_CARD_THEME[type];
  return `<span class="cic" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}">${swatchEmblemHtml(type)}</span>`;
};

const shell = (title, body, { crumb = '' } = {}) => `
<div class="scr">
  <div class="topbar"><div class="brand"><i></i>IHV 発行ポータル<small>CREDENTIAL ISSUER</small></div>
    <div class="who"><span class="av">田</span>田中 ▾</div></div>
  <div class="demo">本デモ中の組織・人物・デジタル資格証明等は全て架空のものです</div>
  <div class="wrap">
    ${crumb ? `<div class="crumb">${crumb}</div>` : ''}
    <h1>${title}</h1>
    ${body}
  </div>
</div>`;

// ---- 1) 申請できる手続き（カタログ下段から遷移） ---------------------------
const s1 = shell('発行申請', `
<p class="lead">交付に自治体の審査が必要なクレデンシャルです。申請して認定を受けると、発行カタログから交付できるようになります。</p>
<div class="list">
  <a class="prow">${sw('disaster')}<div class="pb"><b>罹災証明書の交付申請</b>
    <small>被災した住家の被害程度について、市区町村の被害認定調査を受けます</small>
    <span class="meta">災害対策基本法 第90条の2 ／ 手数料 無料 ／ 標準処理期間 約1週間</span></div><span class="ch">›</span></a>
  <a class="prow">${sw('island')}<div class="pb"><b>離島割引資格証の交付申請</b>
    <small>島民・準島民の区分について、交付自治体の審査を受けます</small>
    <span class="meta">有人国境離島法 ほか ／ 手数料 無料 ／ 標準処理期間 約2週間</span></div><span class="ch">›</span></a>
</div>
<div class="tip">💡 申請中・認定済みの状況は <b>メニュー › 申請一覧</b> で確認できます。</div>`);

// ---- 2) 申請フォーム（罹災） ------------------------------------------------
const s2 = shell('罹災証明書の交付申請', `
<div class="steps"><span class="st on">1 入力</span><span class="sp">›</span><span class="st">2 確認</span><span class="sp">›</span><span class="st">3 受付完了</span></div>
<div class="card">
  <div class="sec">申請者（世帯主）<span class="tagro">住民基本台帳から自動入力</span></div>
  <div class="g2">
    <div class="f"><label>氏名</label><div class="ro">田中 美咲</div></div>
    <div class="f"><label>生年月日</label><div class="ro">2002-04-10</div></div>
  </div>
  <div class="f"><label>世帯主住所</label><div class="ro">大阪府大阪市北区梅田1-1</div></div>

  <div class="sec">被災した住家</div>
  <div class="f"><label>被災住家の所在地 <b class="req">必須</b></label>
    <input value="熊本県熊本市中央区大江3-1-5">
    <span class="hint">世帯主住所と異なる場合（別宅・転居前など）はその住所を入力してください</span></div>
  <div class="f"><label>住家の種別</label>
    <select><option>木造2階建</option><option>木造平屋</option><option>非木造（共同住宅）</option></select></div>

  <div class="sec">罹災原因</div>
  <div class="g2">
    <div class="f"><label>罹災日 <b class="req">必須</b></label><input value="2026-07-28"></div>
    <div class="f"><label>災害名 <b class="req">必須</b></label><input value="令和8年 熊本地震"></div>
  </div>

  <div class="sec">被害の状況（申告）</div>
  <div class="f"><label>被害の状況 <b class="req">必須</b></label>
    <textarea rows="3">地震により1階部分の柱が傾き、居住できない状態です。外壁に大きな亀裂があります。</textarea></div>
  <div class="f"><label>被害状況の写真・書類 <b class="req">必須</b></label>
    <div class="up">
      <div class="upi"><span class="th">📷</span><div class="un"><b>被害 写真 1.jpg</b><small>JPEG 画像 ／ 1.1 MB</small></div><button class="rm">✕</button></div>
      <div class="upi"><span class="th">🖼️</span><div class="un"><b>外壁の亀裂.png</b><small>PNG 画像 ／ 820 KB</small></div><button class="rm">✕</button></div>
      <div class="upi"><span class="th pdf">PDF</span><div class="un"><b>被害状況報告.pdf</b><small>PDF 書類 ／ 640 KB</small></div><button class="rm">✕</button></div>
      <div class="upi bad"><span class="th ng">!</span><div class="un"><b>IMG_4821.HEIC</b><small class="e">HEIC/HEIF 形式は現在ご利用いただけません。JPEG で保存し直すか、撮影時のフォーマットを「互換性優先」にしてください</small></div><button class="rm">✕</button></div>
      <div class="upi bad"><span class="th ng">!</span><div class="un"><b>report.svg</b><small class="e">対応していない形式です（JPEG / PNG / PDF）</small></div><button class="rm">✕</button></div>
      <label class="updrop"><input type="file" multiple accept="image/jpeg,image/png,application/pdf">
        <span class="ic">＋</span><b>写真・書類を追加</b>
        <small>カメラで撮影／ファイルから選択　JPEG・PNG・PDF ／ 1ファイル 8MB まで（最大6件）</small></label>
    </div>
    <span class="hint">被害が軽微で「準半壊に至らない（一部損壊）」の判定に同意できる場合は、写真による自己判定方式を選べます</span></div>

  <div class="warn">⚠️ <b>被害の程度（全壊・半壊など）は申請者が記入する項目ではありません。</b>
    市区町村の被害認定調査によって判定され、認定後に罹災証明書へ記載されます。</div>

  <div class="acts"><button class="btn">確認へ進む</button><button class="btn gh">下書き保存</button></div>
</div>`, { crumb: '発行申請 › 罹災証明書' });

// ---- 3) 申請フォーム（離島）＝汎用性の確認 ---------------------------------
const s3 = shell('離島割引資格証の交付申請', `
<div class="steps"><span class="st on">1 入力</span><span class="sp">›</span><span class="st">2 確認</span><span class="sp">›</span><span class="st">3 受付完了</span></div>
<div class="card">
  <div class="sec">申請者<span class="tagro">住民基本台帳から自動入力</span></div>
  <div class="g2">
    <div class="f"><label>氏名</label><div class="ro">田中 美咲</div></div>
    <div class="f"><label>生年月日</label><div class="ro">2002-04-10</div></div>
  </div>

  <div class="sec">申請する区分</div>
  <div class="rg">
    <label><input type="radio" name="cat"> <b>島民</b><small>対象離島に住民登録がある</small></label>
    <label class="on"><input type="radio" name="cat" checked> <b>準島民</b><small>島外に住むが、介護・就学などで反復して往来する</small></label>
  </div>
  <div class="f"><label>準島民の事由 <b class="req">必須</b></label>
    <select><option>就学（離島出身・島外の学校に在学）</option><option>介護（要介護の親族の介護で年6回以上来島）</option><option>就業・工事等での反復した来島</option><option>短期滞在型住宅の利用</option></select></div>

  <div class="sec">対象</div>
  <div class="g2">
    <div class="f"><label>対象離島 <b class="req">必須</b></label><input value="種子島"></div>
    <div class="f"><label>交付自治体 <b class="req">必須</b></label><input value="鹿児島県西之表市"></div>
  </div>

  <div class="sec">添付書類<span class="tagro">選んだ区分・事由に応じて変わります</span></div>
  <div class="atts">
    <div class="att"><span class="ok">✓</span><div><b>在学証明書または学生証の写し</b><small>就学の事由を証明するもの</small></div><button class="btn xs gh">添付済み</button></div>
    <div class="att"><span class="ok">✓</span><div><b>公的身分証明書の写し</b><small>本人確認</small></div><button class="btn xs gh">添付済み</button></div>
    <div class="att"><span class="wt">－</span><div><b>証明写真（縦3cm×横2.5cm）</b><small>3か月以内に撮影したもの</small></div><button class="btn xs">選択</button></div>
  </div>

  <div class="warn">⚠️ <b>対象区分（島民・準島民）は申請者が決める項目ではありません。</b>
    交付自治体の審査により認定され、認定後に資格証へ記載されます。</div>

  <div class="acts"><button class="btn">確認へ進む</button><button class="btn gh">下書き保存</button></div>
</div>`, { crumb: '発行申請 › 離島割引資格証' });

// ---- 4) 受付完了 -------------------------------------------------------------
const s4 = shell('申請を受け付けました', `
<div class="steps"><span class="st done">1 入力</span><span class="sp">›</span><span class="st done">2 確認</span><span class="sp">›</span><span class="st on">3 受付完了</span></div>
<div class="card mid">
  <div class="big">✔</div>
  <h2>罹災証明書の交付申請を受け付けました</h2>
  <div class="rcpt"><span>受付番号</span><b>A-0007</b></div>
  <p class="lead">この後、市区町村の職員が<b>被害認定調査</b>を行い、住家の被害の程度を判定します。
    認定されると発行カタログから罹災証明書を交付できるようになります。</p>
  <div class="tl">
    <span class="ti on">受付</span><span class="tb"></span><span class="ti">調査中</span><span class="tb"></span><span class="ti">認定</span><span class="tb"></span><span class="ti">交付可能</span>
  </div>
  <div class="acts mid"><button class="btn gh">申請一覧を見る</button><button class="btn gh">発行カタログへ戻る</button></div>
</div>`, { crumb: '発行申請 › 罹災証明書 › 受付完了' });

const chip = (k, t) => `<span class="chip ${k}">${t}</span>`;
// ---- 5) 申請一覧（メニューに追加する画面） ----------------------------------
const s5 = shell('申請一覧', `
<div class="todo">🚧 <b>TODO:</b> 本来この画面は自治体職員向けの管理画面です。現状は暫定として、申請した本人が同じ画面から審査（認定）できるようにしています。</div>
<p class="lead">この発行者が受け付けた交付申請です。<b>審査</b>を行うと、申請者のカタログで該当クレデンシャルが交付できるようになります。</p>
<div class="card p0">
<div class="alist">
  <div class="ahead"><span>受付番号</span><span>種別</span><span>申請の対象</span><span>申請者</span><span>申請日</span><span>状態</span><span></span></div>
  ${[
    ['A-0007', 'disaster', '罹災証明書', '令和8年 熊本地震', '熊本県熊本市中央区大江3-1-5', '2026-08-08', chip('wait', '調査待ち'), '被害認定調査へ'],
    ['A-0006', 'island', '離島割引資格証', '沖縄県石垣市・石垣島', '準島民（就学）', '2026-08-05', chip('doing', '審査中'), '続き'],
    ['A-0005', 'island', '離島割引資格証', '鹿児島県西之表市・種子島', '島民', '2026-03-15', chip('ok', '認定（交付済）'), '詳細'],
    ['A-0003', 'disaster', '罹災証明書', '令和7年台風第10号', '東京都千代田区1-1-1', '2026-06-01', chip('ok', '認定 半壊（交付済）'), '再調査'],
    ['A-0002', 'disaster', '罹災証明書', '令和7年台風第10号', '東京都千代田区9-9-9', '2026-05-30', chip('ng', '却下'), '詳細'],
  ].map(([no, ty, tn, sub1, sub2, day, st, act]) => `<div class="arow">
    <span class="a-meta"><span class="a-no">${no}</span><span class="a-who">田中 美咲</span><span class="a-day">${day}</span></span>
    <span class="a-ty">${sw(ty)}<b>${tn}</b></span>
    <span class="a-sub"><b>${sub1}</b><small>${sub2}</small></span>
    <span class="a-st">${st}</span>
    <span class="a-act"><a class="lk">${act} ›</a></span>
  </div>`).join('')}
</div>
</div>`);

// ---- 6) 審査＝被害認定調査・判定 --------------------------------------------
const s6 = shell('被害認定調査・判定', `
<div class="todo">🚧 <b>TODO:</b> 管理者向け画面へ分離予定。現状は申請者本人が審査できる暫定運用です。</div>
<div class="two">
  <div class="card">
    <div class="sec">申請内容（被災者からの申告）<span class="tagro">受付 A-0007</span></div>
    <div class="f"><label>申請者（世帯主）</label><div class="ro">田中 美咲</div></div>
    <div class="f"><label>世帯主住所</label><div class="ro">大阪府大阪市北区梅田1-1</div></div>
    <div class="f"><label>被災住家の所在地</label><div class="ro">熊本県熊本市中央区大江3-1-5</div></div>
    <div class="f"><label>罹災原因</label><div class="ro">2026-07-28 の 令和8年 熊本地震 による</div></div>
    <div class="f"><label>被害の状況（申告）</label><div class="ro sm">地震により1階部分の柱が傾き、居住できない状態です。外壁に大きな亀裂があります。</div></div>
    <div class="f"><label>添付（3件）</label>
      <div class="ph"><div>📷</div><div>🖼️</div></div>
      <div class="up" style="margin-top:7px">
        <div class="upi"><span class="th pdf">PDF</span><div class="un"><b>被害状況報告.pdf</b><small>PDF 書類 ／ インライン表示せずダウンロードして確認</small></div><a class="lk">開く</a></div>
      </div></div>
    <div class="sec">世帯構成員<span class="tagro">住民基本台帳から連携（参考）</span></div>
    <table class="tb3">
      <tr><th>氏名</th><th>続柄</th><th>生年月日</th></tr>
      <tr><td>田中 美咲</td><td>世帯主</td><td>2002-04-10</td></tr>
      <tr><td>田中 健一</td><td>父</td><td>1974-02-11</td></tr>
      <tr><td>田中 由紀</td><td>母</td><td>1976-09-30</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="sec">被害認定の判定入力</div>
    <p class="lead sm">現地調査および写真に基づき、内閣府「災害の被害認定基準」により住家の被害の程度を判定します。</p>
    <div class="rg tight">
      <label class="on"><input type="radio" name="d" checked> <b>全壊</b><small>損害割合 50%以上</small></label>
      <label><input type="radio" name="d"> <b>大規模半壊</b><small>40%以上 50%未満</small></label>
      <label><input type="radio" name="d"> <b>中規模半壊</b><small>30%以上 40%未満</small></label>
      <label><input type="radio" name="d"> <b>半壊</b><small>20%以上 30%未満</small></label>
      <label><input type="radio" name="d"> <b>準半壊</b><small>10%以上 20%未満</small></label>
      <label><input type="radio" name="d"> <b>準半壊に至らない（一部損壊）</b><small>10%未満</small></label>
    </div>
    <div class="f"><label>追加記載事項（任意）</label><input placeholder="例: 床上浸水、土地の一部流出 など"></div>
    <div class="f"><label>世帯構成員を証明書に記載する</label>
      <label class="sws"><input type="checkbox" checked> 記載する（内閣府統一様式の追加記載事項欄①）</label></div>
    <div class="warn">💡 <b>被害の程度はこの判定で確定します。</b>申請書には記載されず、市区町村の被害認定調査によって決まります。</div>
    <div class="acts col"><button class="btn">この内容で認定する</button>
      <button class="btn gh">却下する</button><button class="btn gh">一覧に戻る</button></div>
  </div>
</div>`, { crumb: '申請一覧 › A-0007' });

// ---- 7) 認定完了（交付可能になった） ----------------------------------------
const s7 = shell('認定しました', `
<div class="card mid">
  <div class="big">✔</div>
  <h2>受付 A-0007 を認定しました</h2>
  <div class="rcpt"><span>被害の程度</span><b class="dmg">全壊</b></div>
  <p class="lead">申請者の発行カタログで <b>罹災証明書</b> が交付できるようになりました。</p>
  <div class="prev">
    <div class="pvh">${sw('disaster')}<div><b>交付される内容</b><small>認定にもとづき自動生成されます</small></div></div>
    <div class="pv"><span>世帯主氏名</span><b>田中 美咲</b></div>
    <div class="pv"><span>世帯主住所</span><b>大阪府大阪市北区梅田1-1</b></div>
    <div class="pv"><span>被災住家の所在地</span><b>熊本県熊本市中央区大江3-1-5</b></div>
    <div class="pv"><span>罹災原因</span><b>2026-07-28 の 令和8年 熊本地震 による</b></div>
    <div class="pv"><span>住家の被害の程度</span><b class="dmg">全壊</b></div>
    <div class="pv"><span>世帯構成員</span><b>田中 美咲（世帯主）／田中 健一（父）／田中 由紀（母）</b></div>
    <div class="pv"><span>整理番号</span><b>DS-0007</b></div>
    <div class="pv"><span>発行者</span><b>熊本市長</b></div>
  </div>
  <div class="acts mid"><button class="btn gh">申請一覧へ戻る</button></div>
</div>`, { crumb: '申請一覧 › A-0007 › 認定' });

// ---- 8) 再判定 → 既発行の失効 ------------------------------------------------
const s8 = shell('再調査による判定の変更', `
<div class="card">
  <div class="sec">受付 A-0003 ／ 令和7年台風第10号</div>
  <div class="diff">
    <div class="dcol"><span class="dh">現在の認定</span><b class="dmg">半壊</b><small>2026-06-01 認定・交付済み</small></div>
    <div class="darw">→</div>
    <div class="dcol"><span class="dh">再調査の判定</span><b class="dmg">全壊</b><small>2026-08-08</small></div>
  </div>
  <div class="warn danger">⚠️ <b>交付済みの罹災証明書は失効します。</b>
    証明書に記載された被害の程度が変わるため、この申請から発行された次の2件を失効させ、新しい内容で再交付できるようにします。
    <div class="revl">
      <div class="rev">${sw('disaster')}<div><b>罹災証明書（mdoc）</b><small>2026-06-02 交付 ／ status idx 41</small></div><span class="chip ng">失効させる</span></div>
      <div class="rev">${sw('disaster')}<div><b>罹災証明書（SD-JWT VC）</b><small>2026-06-02 交付 ／ status idx 42</small></div><span class="chip ng">失効させる</span></div>
    </div>
  </div>
  <div class="note2">🔎 判定が変わらない場合（例: 全壊 → 全壊）は、証明書に載る内容が同じなので<b>失効させません</b>。
    交付内容のハッシュを比較し、差分があるときだけ失効します。</div>
  <div class="acts"><button class="btn danger">判定を変更し、交付済みを失効させる</button><button class="btn gh">やめる</button></div>
</div>`, { crumb: '申請一覧 › A-0003 › 再調査' });

const CSS = `
:root{--line:#DCE3ED;--muted:#5B6B82;--ink:#0E1A2B;--civic:#1C3F94;--seal:#C8453C}
*{box-sizing:border-box}
body{font-family:'Hiragino Sans','Noto Sans JP',sans-serif;background:#eef1f5;color:var(--ink);margin:0;padding:20px}
.scr{background:#F4F6FA;border-radius:16px;overflow:hidden;margin-bottom:26px;box-shadow:0 2px 14px rgba(0,0,0,.07)}
.topbar{background:#E8EEF9;display:flex;align-items:center;padding:12px 22px;border-bottom:1px solid #d8e0ef}
.brand{font-size:15px;font-weight:800;display:flex;align-items:center;gap:9px}
.brand i{width:5px;height:20px;background:var(--civic);border-radius:2px;display:inline-block}
.brand small{display:block;font-size:9px;letter-spacing:.14em;color:var(--muted);font-weight:600}
.who{margin-left:auto;display:flex;align-items:center;gap:7px;font-size:13px;font-weight:600;background:#fff;border:1px solid var(--line);border-radius:999px;padding:3px 12px 3px 4px}
.av{width:26px;height:26px;border-radius:50%;border:2px solid var(--seal);color:var(--seal);display:grid;place-items:center;font-size:12px;font-weight:700}
.demo{background:#FDF7E3;font-size:11px;padding:6px 22px;color:#6b5a1e}
.wrap{padding:22px 26px 30px}
.crumb{font-size:11.5px;color:var(--muted);margin-bottom:6px}
h1{font-size:20px;margin:0 0 12px}
h2{font-size:17px;margin:6px 0 8px}
.lead{font-size:12.5px;color:var(--muted);line-height:1.8;margin:0 0 14px}
.lead.sm{font-size:12px;margin-bottom:10px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin-bottom:12px}
.card.p0{padding:0;overflow:hidden}.card.mid{text-align:center}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start}
${swatchEmblemCss()}
.cic{width:34px;height:34px;border-radius:9px;display:inline-grid;place-items:center;vertical-align:middle;flex:none;
  background:radial-gradient(120% 90% at 85% -12%,var(--c3) 0%,transparent 55%),linear-gradient(135deg,var(--c1) 0%,var(--c2) 100%);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 1px 2px rgba(0,0,0,.18)}
.cic .swemb{display:block;width:72%;height:72%;color:rgba(255,255,255,.95);filter:drop-shadow(0 1px 0 rgba(0,0,0,.4))}
/* 手続き一覧 */
.list{display:flex;flex-direction:column;gap:10px}
.prow{display:flex;gap:14px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:14px;padding:15px 18px;text-decoration:none;color:inherit}
.pb{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}
.pb b{font-size:14px}.pb small{font-size:11.5px;color:var(--muted)}
.pb .meta{font-size:10.5px;color:#8A97AB;margin-top:3px}
.ch{color:#8A97AB;font-size:22px}
.tip{background:#EAF0FA;border-radius:10px;padding:11px 14px;font-size:12px;color:#26406f;margin-top:12px}
/* フォーム */
.steps{display:flex;align-items:center;gap:8px;margin-bottom:12px}
.st{font-size:11.5px;font-weight:700;color:var(--muted);background:#fff;border:1px solid var(--line);border-radius:999px;padding:5px 13px}
.st.on{background:var(--civic);border-color:var(--civic);color:#fff}
.st.done{background:#E7F3EE;border-color:#bfe3d5;color:#0E8A6B}
.sp{color:#b9c3d4;font-size:12px}
.sec{font-size:12px;font-weight:800;color:var(--civic);letter-spacing:.03em;margin:16px 0 9px;padding-bottom:5px;border-bottom:1px solid #eaeff7;display:flex;align-items:center}
.sec:first-child{margin-top:0}
.tagro{margin-left:auto;font-weight:600;font-size:10.5px;color:var(--muted);background:#F3F5F9;border-radius:6px;padding:2px 8px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
.f{margin-bottom:13px}
.f label{display:block;font-size:11.5px;font-weight:700;color:#3d4d63;margin-bottom:5px}
.req{color:#fff;background:var(--seal);border-radius:4px;font-size:9.5px;padding:1px 5px;margin-left:5px;vertical-align:1px}
.f input,.f select,.f textarea{width:100%;font:inherit;font-size:13px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:#fff}
.ro{background:#F3F5F9;border-radius:8px;padding:9px 11px;font-size:13px}
.ro.sm{font-size:12px;line-height:1.7}
.hint{display:block;font-size:10.5px;color:#8A97AB;margin-top:4px;line-height:1.6}
.ph{display:flex;gap:8px}
.ph div{width:64px;height:64px;background:#E4E9F1;border-radius:9px;display:grid;place-items:center;font-size:24px}
.ph .add{background:#fff;border:1.5px dashed #c3cede;color:#8A97AB;font-size:20px}
.rg{display:flex;flex-direction:column;gap:7px}
.rg label{display:block;border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px;background:#fff}
.rg label.on{border-color:var(--civic);background:#F4F7FD;box-shadow:0 0 0 1px var(--civic) inset}
.rg label b{font-size:13px}.rg label small{display:block;font-size:10.5px;color:var(--muted);margin-top:1px;margin-left:22px}
.rg.tight label{padding:7px 11px}
.sws{font-size:12px;font-weight:500!important;color:#3d4d63}
.atts{display:flex;flex-direction:column;gap:8px}
.att{display:flex;align-items:center;gap:11px;border:1px solid var(--line);border-radius:9px;padding:10px 13px}
.att b{font-size:12.5px;display:block}.att small{font-size:10.5px;color:var(--muted)}
.att>div{flex:1}
.att .ok{color:#0E8A6B;font-weight:800}.att .wt{color:#b9c3d4;font-weight:800}
.warn{background:#FDF7E3;border-radius:10px;padding:12px 14px;font-size:11.5px;color:#6b5a1e;line-height:1.8;margin:14px 0}
.warn.danger{background:#FDECEA;color:#8a2b22}
.note2{background:#EAF0FA;border-radius:10px;padding:12px 14px;font-size:11.5px;color:#26406f;line-height:1.8;margin:12px 0}
.todo{background:#F3F5F9;border:1px dashed #c3cede;border-radius:10px;padding:11px 14px;font-size:11.5px;color:var(--muted);line-height:1.7;margin-bottom:12px}
.acts{display:flex;gap:10px;margin-top:16px}
.acts.mid{justify-content:center}.acts.col{flex-direction:column}
.btn{font:inherit;font-size:13.5px;font-weight:700;padding:11px 22px;border-radius:9px;border:0;background:var(--civic);color:#fff}
.btn.gh{background:#fff;border:1px solid var(--line);color:var(--civic)}
.btn.danger{background:var(--seal)}
.btn.xs{font-size:11px;padding:6px 12px}
/* 受付完了 */
.big{font-size:46px;color:#0E8A6B;line-height:1.2}
.rcpt{display:inline-flex;align-items:center;gap:12px;background:#F3F5F9;border-radius:10px;padding:10px 18px;margin:8px 0 12px}
.rcpt span{font-size:11.5px;color:var(--muted)}
.rcpt b{font-size:19px;font-family:ui-monospace,monospace}
.rcpt b.dmg{font-family:inherit;color:var(--seal)}
.tl{display:flex;align-items:center;justify-content:center;gap:6px;margin:14px 0 4px}
.ti{font-size:11px;font-weight:700;color:var(--muted);background:#fff;border:1px solid var(--line);border-radius:999px;padding:5px 13px}
.ti.on{background:var(--civic);border-color:var(--civic);color:#fff}
.tb{width:22px;height:2px;background:#d8e0ef}
/* 一覧: PC=表組み / SP=カード を1マークアップで両立 */
.alist{display:flex;flex-direction:column}
.ahead,.arow{display:grid;grid-template-columns:86px 150px minmax(0,1fr) 84px 96px 132px auto;
  column-gap:12px;align-items:center;padding:11px 16px}
.ahead{font-size:10.5px;color:var(--muted);font-weight:700;background:#F7F9FC;border-bottom:1px solid var(--line)}
.arow{border-bottom:1px solid #eef1f6;font-size:12.5px}
.arow:last-child{border-bottom:0}
.a-meta{display:contents}
.a-no{grid-column:1;font-family:ui-monospace,monospace;font-size:12px}
.a-who{grid-column:4}.a-day{grid-column:5}
.a-ty{grid-column:2}.a-sub{grid-column:3}.a-st{grid-column:6}.a-act{grid-column:7}
.a-ty{display:flex;align-items:center;gap:8px;min-width:0}
.a-ty b{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.a-sub{min-width:0;display:flex;flex-direction:column;line-height:1.45}
.a-sub b{font-size:12.5px;font-weight:500}
.a-sub small{font-size:10.5px;color:var(--muted)}
.a-act{white-space:nowrap}
.tb3{width:100%;border-collapse:collapse;background:#F7F9FC;border-radius:9px;overflow:hidden}
.tb3 th{font-size:10.5px;color:var(--muted);text-align:left;padding:8px 11px;background:#E9EEF6}
.tb3 td{font-size:12px;padding:8px 11px;border-top:1px solid #e6ebf3}
/* 認定プレビュー */
.prev{border:1px solid var(--line);border-radius:12px;overflow:hidden;text-align:left;max-width:520px;margin:6px auto 0}
.pvh{display:flex;align-items:center;gap:11px;padding:12px 15px;background:#F7F9FC;border-bottom:1px solid var(--line)}
.pvh b{font-size:13px;display:block}.pvh small{font-size:10.5px;color:var(--muted)}
.pv{display:flex;justify-content:space-between;gap:16px;padding:9px 15px;border-bottom:1px solid #f0f3f8;font-size:12px}
.pv:last-child{border-bottom:0}
.pv span{color:var(--muted);flex:none}
.pv b{text-align:right}.pv b.dmg{color:var(--seal)}
/* 添付アップロード */
.up{display:flex;flex-direction:column;gap:7px}
.upi{display:flex;align-items:center;gap:11px;border:1px solid var(--line);border-radius:9px;padding:8px 11px;background:#fff}
.upi.bad{border-color:#f0cfcb;background:#FEF6F5}
.upi .th{width:38px;height:38px;border-radius:7px;background:#E4E9F1;display:grid;place-items:center;font-size:19px;flex:none}
.upi .th.pdf{background:#FDECEA;color:#b3261e;font-size:11px;font-weight:800}
.upi .th.ng{background:#FDECEA;color:#b3261e;font-size:20px;font-weight:800}
.upi .un{flex:1;min-width:0}
.upi .un b{display:block;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.upi .un small{font-size:10.5px;color:var(--muted)}
.upi .un small.e{color:#b3261e}
.upi .rm{border:0;background:none;color:#8A97AB;font-size:14px;padding:4px 6px}
.updrop{display:flex;flex-direction:column;align-items:center;gap:2px;border:1.5px dashed #c3cede;border-radius:10px;
  padding:14px 12px;background:#FAFBFD;text-align:center}
.updrop input{display:none}
.updrop .ic{font-size:20px;color:var(--civic)}
.updrop b{font-size:12.5px;color:var(--civic)}
.updrop small{font-size:10.5px;color:var(--muted);line-height:1.6}
/* ---- スマートフォン（〜640px） ---- */
@media(max-width:640px){
  body{padding:10px}
  .wrap{padding:16px 14px 22px}
  .topbar{padding:10px 14px}.demo{padding:6px 14px}
  h1{font-size:17px}
  .card{padding:16px 15px;border-radius:12px}
  .two{grid-template-columns:1fr}
  .g2{grid-template-columns:1fr}
  .steps{flex-wrap:wrap;gap:6px}.st{font-size:11px;padding:4px 11px}
  .acts{flex-direction:column}.btn{width:100%;padding:13px 18px}
  .prow{padding:13px 14px;gap:11px}
  .ph div{width:56px;height:56px}
  /* 申請一覧: 表組み → カード（1行=1カード） */
  .ahead{display:none}
  .arow{grid-template-columns:32px minmax(0,1fr) auto;gap:2px 9px;padding:13px 14px;
    border-bottom:8px solid #F4F6FA;align-items:start}
  .a-ty{grid-column:1/3!important;grid-row:1}
  .a-ty .cic{width:32px;height:32px;border-radius:8px}
  .a-ty b{font-size:13px;font-weight:700}
  .a-st{grid-column:3!important;grid-row:1;justify-self:end}
  .a-sub{grid-column:1/-1!important;grid-row:2;margin-top:5px}
  .a-sub b{font-size:14px;font-weight:700}
  .a-sub small{font-size:11.5px;margin-top:1px}
  .a-meta{display:flex;flex-wrap:wrap;gap:4px 10px;grid-column:1/-1;grid-row:3;margin-top:7px;
    font-size:11px;color:var(--muted)}
  .a-meta>span{grid-column:auto!important}
  .a-no{font-family:ui-monospace,monospace}
  .a-act{grid-column:1/-1!important;grid-row:4;text-align:right;margin-top:9px;padding-top:9px;border-top:1px solid #eef1f6}
  .a-act .lk{font-size:13px}
  /* 判定の差分表示を縦積みに */
  .diff{flex-direction:column;gap:8px}
  .darw{transform:rotate(90deg)}
  .dcol{width:100%}
  .prev{max-width:none}
  .pv{flex-direction:column;gap:2px}.pv b{text-align:left}
  .tl{flex-wrap:wrap;justify-content:flex-start}
  .rcpt{width:100%;justify-content:center}
  .att{flex-wrap:wrap}.att .btn{margin-left:auto}
}
/* 再判定 */
.diff{display:flex;align-items:center;justify-content:center;gap:22px;margin:6px 0 14px}
.dcol{text-align:center;background:#F7F9FC;border-radius:11px;padding:13px 26px;min-width:180px}
.dh{display:block;font-size:10.5px;color:var(--muted);margin-bottom:4px}
.dcol b{font-size:20px}.dcol b.dmg{color:var(--seal)}
.dcol small{display:block;font-size:10.5px;color:#8A97AB;margin-top:3px}
.darw{font-size:22px;color:#b9c3d4}
.revl{display:flex;flex-direction:column;gap:7px;margin-top:10px}
.rev{display:flex;align-items:center;gap:11px;background:#fff;border:1px solid #f0cfcb;border-radius:9px;padding:9px 12px}
.rev b{font-size:12.5px;display:block;color:var(--ink)}.rev small{font-size:10.5px;color:var(--muted)}
.rev>div{flex:1}
`;

const SCREENS = [
  ['01-apply-list', s1], ['02-form-disaster', s2], ['03-form-island', s3], ['04-received', s4],
  ['05-applications', s5], ['06-review', s6], ['07-approved', s7], ['08-rejudge-revoke', s8],
];
// viewport メタが無いとモバイルエミュレーションが既定 980px で組んでしまい、
// メディアクエリ（max-width:640px）が効かない
const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${CSS}</style></head><body>
<div style="max-width:1020px;margin:0 auto">${SCREENS.map(([, h]) => h).join('')}</div>
</body></html>`;
const file = fileURLToPath(new URL('../web/captures/mock-flow.html', import.meta.url));
writeFileSync(file, html);

const browser = await chromium.launch();
// PC
const page = await browser.newPage({ viewport: { width: 1060, height: 900 }, deviceScaleFactor: 2 });
await page.goto('file://' + file);
await page.waitForTimeout(400);
const els = await page.$$('.scr');
for (const [i, [name]] of SCREENS.entries()) {
  if (els[i]) await els[i].screenshot({ path: out + `mock-flow-${name}.png` });
}
// スマートフォン（390px）
const sp = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
await sp.goto('file://' + file);
await sp.waitForTimeout(400);
const spEls = await sp.$$('.scr');
for (const [i, [name]] of SCREENS.entries()) {
  if (spEls[i]) await spEls[i].screenshot({ path: out + `mock-sp-${name}.png` });
}
await browser.close();
console.log('mock -> web/captures/mock-flow-*.png');
