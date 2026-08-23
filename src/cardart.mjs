// 券面（cardArt）の正本。**1つの SVG から Web もメタデータも作る**。
//
// これまで意匠が2箇所にあった——Web の `.vcard` は CSS グラデーション、Multipaz へ渡す
// メタデータは `scripts/gen-cardart.mjs` が別に組んだ SVG をラスタライズしたもの。
// 同じ資格証なのに見た目が揃わず、片方を直しても片方に反映されなかった。
// ここを唯一の意匠にして、**Web はこの SVG をそのままインライン**（画像化しない＝
// どの寸法でも滲まず、JPEG より小さい）、**メタデータはこれを描画して JPEG 化**する。
//
// この層は fs を使わない（Workers で import される）。和英名は **`schemas/*.json` の
// `display`** から引く——生成器 `gen-schemas.mjs` の出力そのものなので、
// 名前の正本は1つのまま（2箇所に書くとメタデータの name と券面の文字がずれ、
// 券面は画像なので気づきにくい）。
import pid from '../schemas/pid.json' with { type: 'json' };
import juminhyo from '../schemas/juminhyo.json' with { type: 'json' };
import qualification from '../schemas/qualification.json' with { type: 'json' };
import koseki from '../schemas/koseki.json' with { type: 'json' };
import tax from '../schemas/tax.json' with { type: 'json' };
import single from '../schemas/single.json' with { type: 'json' };
import disaster from '../schemas/disaster.json' with { type: 'json' };
import vaccine from '../schemas/vaccine.json' with { type: 'json' };
import island from '../schemas/island.json' with { type: 'json' };
import { esc } from './html.mjs';

/** 和英名。スキーマ束（gen-schemas.mjs の出力）から引くので定義は1箇所のまま。 */
export const DISPLAY_NAMES = Object.fromEntries(
  Object.entries({ pid, juminhyo, qualification, koseki, tax, single, disaster, vaccine, island })
    .map(([id, s]) => [id, { ja: s.display?.ja ?? id, en: s.display?.en ?? id }]));

// ---- wallet card visual system (shared by the web wallet + issuer consent) ----
// 8 documents × Japanese-palette gradients: c1→c2 base, c3 = top-right glow.
export const WALLET_CARD_THEME = {
  pid: { c1: '#2B3A8F', c2: '#1A2565', c3: '#7C6FE0' },          // 紺+菖蒲
  juminhyo: { c1: '#00796B', c2: '#004D40', c3: '#66D9C4' },     // 深緑+若竹
  qualification: { c1: '#7B1FA2', c2: '#4A0E7A', c3: '#CE93D8' },// 紫+藤
  koseki: { c1: '#5D4037', c2: '#3E2723', c3: '#C9A227' },       // 焦茶+金茶
  tax: { c1: '#2E7D32', c2: '#124D18', c3: '#9CCC65' },          // 緑+若葉
  single: { c1: '#AD1457', c2: '#7B0F3E', c3: '#F48FB1' },       // 茜+撫子
  disaster: { c1: '#D84315', c2: '#93290A', c3: '#FFB74D' },     // 柿
  vaccine: { c1: '#0277BD', c2: '#014377', c3: '#4FC3F7' },      // 空
  // 山吹（金茶）— 現行8色に黄系が無く、住民票の深緑・課税の緑・罹災の柿のいずれとも
  // スウォッチ列で判別できる。錆浅葱は住民票と同系に見えたため 2026-07-27 に差し替え
  island: { c1: '#C97A00', c2: '#7A4200', c3: '#FFD54F' },        // 山吹
};

// カード面の行頭エンブレム（案E1 浮き彫り）用の単色シルエット。8種＋fallback。
export const CARD_SIL = {
  pid: `<path d="M3 5.5h18c.6 0 1 .4 1 1v11c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1v-11c0-.6.4-1 1-1zM7 9a2.2 2.2 0 100 4.4A2.2 2.2 0 007 9zm6 .3h6V11h-6zm0 3h5v1.6h-5zM5 15.6h8v1.6H5z"/>`,
  juminhyo: `<path d="M12 3 2 11.2h3V20h5v-5.5h4V20h5v-8.8h3z"/>`,
  qualification: `<path d="M12 4 1 9l11 5 9-4.1V15.5h1.8V9zM4.5 12.4v3.1C4.5 17.3 8 18.6 12 18.6s7.5-1.3 7.5-3.1v-3.1L12 15.8z"/>`,
  koseki: `<path d="M6 3h8l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zm2 7h8v1.6H8zm0 3.2h8v1.6H8zm0 3.2h5v1.6H8z"/>`,
  tax: `<path d="M6 2l1.5 1.2L9 2l1.5 1.2L12 2l1.5 1.2L15 2l1.5 1.2L18 2v18l-1.5-1.2L15 20l-1.5 1.2L12 20l-1.5-1.2L9 20l-1.5 1.2L6 22zm2.5 5h7v1.6h-7zm0 3.2h7v1.6h-7zm0 3.2h4.5v1.6H8.5z"/>`,
  single: `<path d="M12 8.2a4.4 4.4 0 100 8.8 4.4 4.4 0 000-8.8zm0 1.8a2.6 2.6 0 110 5.2 2.6 2.6 0 010-5.2zM9.6 2h4.8l1.3 3.1-3.7 2.3L8.3 5.1z"/>`,
  disaster: `<path d="M12 3 2 11h3v9h6.2l-1.3-3 2.6-2-2-2.4 2.5-1.8V20h6v-9h3z"/>`,
  // 離島割引資格証: 島影（大小の丘）＋波。飛行機にすると「搭乗券」に見えてしまうので島にした
  island: `<path d="M12 4.2c-4.9 0-8.9 3.9-9.9 9h19.8c-1-5.1-5-9-9.9-9z"/><path d="M2 16.3c1.67 0 1.67 1.3 3.33 1.3S7 16.3 8.67 16.3s1.66 1.3 3.33 1.3 1.67-1.3 3.33-1.3 1.67 1.3 3.34 1.3S20.33 16.3 22 16.3v2.1c-1.67 0-1.67 1.3-3.33 1.3s-1.67-1.3-3.34-1.3-1.66 1.3-3.33 1.3-1.67-1.3-3.33-1.3S7 19.7 5.33 19.7 3.67 18.4 2 18.4z"/>`,
  vaccine: `<g transform="rotate(-40 12 12)"><rect x="1.6" y="11.25" width="6" height="1.5" rx=".2"/><rect x="7.4" y="7.8" width="1.7" height="8.4" rx=".4"/><rect x="9" y="9" width="7.6" height="6" rx=".7"/><rect x="11" y="9.3" width="1" height="1.6"/><rect x="12.8" y="9.3" width="1" height="1.6"/><rect x="14.6" y="9.3" width="1" height="1.6"/><rect x="16.4" y="6.6" width="1.9" height="10.8" rx=".4"/><rect x="18.3" y="10.8" width="2.2" height="2.4"/><rect x="20.2" y="8.6" width="1.8" height="6.8" rx=".4"/></g>`,
};
// シルエットの視覚中心・大きさを 24×24 枠に合わせる微調整（bbox のズレ/小ささ補正）。
// swatch と券面エンボスの両方に効かせ、全面で同じ位置・比率に見せる。
//   dx/dy=平行移動, s=中心(cx,cy)まわりの拡大。single は指輪が細身で小さく見えるため拡大。
const CARD_SIL_ADJ = {
  single: { s: 1.22, cx: 12, cy: 11, dy: 2 },
  koseki: { dx: 0.8 },
};
// **位置補正込みの字形**。issuer カタログの紋章と券面画像（scripts/gen-cardart.mjs）で
// 同じものを使う——補正を片方だけに掛けると、同じ資格証なのに紋章の位置がずれる
export function embInner(type) {
  const p = CARD_SIL[type];
  if (!p) return '';
  const a = CARD_SIL_ADJ[type];
  if (!a) return p;
  const dx = a.dx || 0, dy = a.dy || 0, s = a.s || 1, cx = a.cx ?? 12, cy = a.cy ?? 12;
  const parts = [];
  if (dx || dy) parts.push(`translate(${dx} ${dy})`);
  if (s !== 1) parts.push(`translate(${cx} ${cy}) scale(${s}) translate(${-cx} ${-cy})`);
  return `<g transform="${parts.join(' ')}">${p}</g>`;
}

// ---- 券面 SVG ----------------------------------------------------------------
// ID-1 比（85.6 × 54mm）。**一覧では上端しか見えない**ので、書類名と紋章は上 26% に収める
// （実機 Multipaz で計測: カード高 497px に対し露出 128px）。我々の Web ウォレットも
// -96px の重なりで同じ制約になる。
export const CARD_W = 428, CARD_H = 270;
const BAND = Math.round(CARD_H * 0.26);
const EM = 52;                        // 紋章の一辺（可視帯に収まる大きさ）
// 文字サイズは**全書類で揃える**。書類ごとに変えると重ねたとき行の高さがばらつく。
// 一番長い名前（PID の英名 36 文字）が収まる寸法に合わせている。
const JA_SIZE = 23, EN_SIZE = 11.5;
// **紋章と文字の上下中心を揃える**（2026-08-23 の指摘）。以前は紋章 y=9（中心 35.0）に対し
// 文字ブロックが 21.2〜61.4（中心 41.3）で **6.3px 下にいた**。テキストは baseline 指定なので
// 「y を揃える」では中心が合わない——キャップハイト(≒.73em)とディセンダ(≒.21em)から
// 視覚的な上下端を出して、両者の中心を 36 に合わせている。
//   紋章 y=10（10〜62・中心 36） / 和名 baseline y=33 / 英名 baseline y=54

/**
 * 券面1枚を SVG で返す。`inline:true` なら Web に直接埋める形（`<style>` を持たず、
 * クラスでなく属性で描く——ページの CSS と衝突させないため）。
 * `inline:false` はラスタライズ用のスタンドアロン文書。
 */
export function cardArtSvg(id, { inline = true, w = CARD_W, h = CARD_H, title = null } = {}) {
  const t = WALLET_CARD_THEME[id] || WALLET_CARD_THEME.pid;
  const sil = embInner(id) || CARD_SIL.pid;
  const nm = DISPLAY_NAMES[id] || { ja: id, en: id };
  const u = `ca-${id}`;               // グラデーション id はカードごとに一意（同一ページに複数出る）
  const label = title ?? `${nm.ja}の券面`;
  // エンボス（浮き彫り）: 不透明に近い白 .92 と二段の drop-shadow（下に影・上にハイライト）。
  // **半透明にすると地色が透けて「浮き彫り」でなく「薄い模様」に見える**。
  // 影の量は字形の大きさに比例させる（26px の字形に 0.7/0.5px なので 52px なら 1.4/1.0px）。
  const emb = 'fill="rgba(255,255,255,.92)" style="filter:drop-shadow(0 1.4px 0 rgba(0,0,0,.40)) drop-shadow(0 -1px .8px rgba(255,255,255,.30))"';
  const jaS = 'fill="#fff" font-family="\'Noto Sans JP\',\'Hiragino Sans\',sans-serif" font-weight="700" style="filter:drop-shadow(0 1.5px 2px rgba(0,0,0,.5))"';
  const enS = 'fill="rgba(255,255,255,.88)" font-family="\'Noto Sans JP\',\'Helvetica Neue\',Arial,sans-serif" font-weight="400" letter-spacing=".01em" style="filter:drop-shadow(0 1px 2px rgba(0,0,0,.45))"';
  const isS = 'fill="rgba(255,255,255,.72)" font-family="\'Noto Sans JP\',\'Helvetica Neue\',Arial,sans-serif" font-weight="700" font-size="14" letter-spacing=".14em"';
  const body = `<defs>
      <linearGradient id="${u}g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="${t.c1}"/><stop offset="62%" stop-color="${t.c2}"/>
        <stop offset="100%" stop-color="${t.c1}"/></linearGradient>
      <linearGradient id="${u}h" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="${t.c3}" stop-opacity="0"/>
        <stop offset="45%" stop-color="${t.c3}" stop-opacity=".28"/>
        <stop offset="100%" stop-color="${t.c3}" stop-opacity="0"/></linearGradient>
    </defs>
    <rect width="${CARD_W}" height="${CARD_H}" fill="url(#${u}g)"/>
    <ellipse cx="${CARD_W * 1.10}" cy="${CARD_H * 1.19}" rx="${CARD_W * 0.77}" ry="${CARD_H * 0.87}" fill="url(#${u}h)"/>
    <g fill="rgba(255,255,255,.10)" transform="translate(${CARD_W - 150} ${CARD_H - 150}) scale(6.2)">${sil}</g>
    <g ${emb} transform="translate(22 10) scale(${EM / 24})">${sil}</g>
    <text x="${22 + EM + 14}" y="33" ${jaS} font-size="${JA_SIZE}">${esc(nm.ja)}</text>
    <text x="${22 + EM + 14}" y="54" ${enS} font-size="${EN_SIZE}">${esc(nm.en)}</text>
    <text x="24" y="${CARD_H - 22}" ${isS}>DEMO VC ISSUER</text>`;
  const open = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${CARD_W} ${CARD_H}"`
    + (inline ? ` role="img" aria-label="${esc(label)}" preserveAspectRatio="xMidYMid slice"`
              : ` width="${w}" height="${h}"`) + '>';
  return `${open}${body}</svg>`;
}
