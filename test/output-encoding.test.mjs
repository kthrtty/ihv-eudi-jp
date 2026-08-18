// 出力エンコーディングの規約をテストで固定する（issue #33 / 2026-08-18 の監査）。
//
// **規約を書くだけでは戻る**——`esc()` が5ファイルに重複し、しかも2種類の挙動になっていたのは
// 自然発生だった（よりによって申請フォームの自由入力を描く2ファイルが `'` を落とさない版）。
// この repo は inline JS が多いので、文脈の取り違えも起きやすい。だから機械で見張る。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { esc, js, jsAttr } from '../src/html.mjs';

const SRC = fileURLToPath(new URL('../src/', import.meta.url));
const files = readdirSync(SRC).filter((f) => f.endsWith('.mjs'));
const read = (f) => readFileSync(SRC + f, 'utf8');

// ---- エンコーダそのもの ----
test('esc: HTML の本文・属性で危険な5文字を落とす', () => {
  assert.equal(esc(`<a href="x" data-y='z'>&</a>`),
    '&lt;a href=&quot;x&quot; data-y=&#39;z&#39;&gt;&amp;&lt;/a&gt;');
  // **`'` を落とす**——一重引用符の属性やイベント属性で文字列を抜けられないように
  assert.equal(esc("it's"), 'it&#39;s');
  assert.equal(esc(null), '');
  assert.equal(esc(undefined), '');
});

test('js: <script> の中でブロックを閉じられない・行区切りで壊れない', () => {
  // **`JSON.stringify` だけでは足りない**: `</script>` でブロックが終わる
  assert.ok(!js('</script><img src=x>').includes('</script>'));
  assert.match(js('</script>'), /\\u003c\\u002fscript\\u003e|\\u003c\/script\\u003e/);
  // U+2028 / U+2029 は JS では行区切り扱いで構文が壊れる
  assert.ok(!js('a b').includes(' '));
  assert.ok(!js('a b').includes(' '));
  // 値は保たれる（HTML エスケープと違い、復号すると原文に戻る）
  for (const v of ["it's", '<b>', 'あ&い', '"q"', 12, null]) {
    assert.deepEqual(JSON.parse(js(v).replace(/\\u003c/g, '<').replace(/\\u003e/g, '>').replace(/\\u0026/g, '&')), v ?? null);
  }
});

test('jsAttr: イベント属性は JS→HTML の二段エンコード', () => {
  // 属性値は **HTML デコードされてから JS として解析される**ので二段が要る
  const out = jsAttr("a'b\"c");
  assert.ok(!out.includes('"'), '生の二重引用符が属性を閉じない');
  assert.ok(!out.includes("'"), '生の一重引用符が残らない');
  // HTML デコードすると JS リテラルとして正しい
  const decoded = out.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  assert.equal(JSON.parse(decoded.replace(/\\u003c/g, '<').replace(/\\u003e/g, '>').replace(/\\u0026/g, '&')), "a'b\"c");
});

// ---- 規約: 実装は1つだけ ----
test('規約: サーバ側の esc の実装は src/html.mjs にしか無い', () => {
  const bad = [];
  for (const f of files) {
    if (f === 'html.mjs') continue;
    // **`<script>` の中は対象外**——ブラウザで動くコードは import できないので、
    // そこに同名の helper があるのは正しい（devlog のコンソール等）
    const server = read(f).replace(/<script[^>]*>[\s\S]*?<\/script>/g, '');
    // **行頭に限定しない**——`const a = 1; const esc = …` のような行中の再定義を見逃す
    for (const m of server.matchAll(/(?:const|let|function)\s+esc\b/g)) {
      bad.push(`${f}: ${m[0].trim()}`);
    }
  }
  assert.deepEqual(bad, [], 'esc をサーバ側で再定義しない（挙動が分かれる）');
});

// ---- 規約: <script> の中で HTML エスケープを使わない ----
test('規約: <script> の中の差し込みは js() を使う（esc() は使わない）', () => {
  const bad = [];
  for (const f of files) {
    const s = read(f);
    for (const blk of s.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) {
      const line = s.slice(0, blk.index).split('\n').length;
      for (const it of blk[1].matchAll(/\$\{([^}]{1,120})\}/g)) {
        const e = it[1];
        // script の中身は HTML デコードされないので、esc() の出力は literal で入る
        if (/\besc\s*\(/.test(e)) bad.push(`${f}:${line} ${e.trim().slice(0, 70)}`);
      }
    }
  }
  assert.deepEqual(bad, [], '<script> 内は js()（JSON エンコード）を使う');
});

// ---- 規約: イベント属性は jsAttr を通す ----
test('規約: on* 属性の差し込みは jsAttr() を使う', () => {
  const bad = [];
  for (const f of files) {
    const s = read(f);
    // on<name>="....${...}...." の属性を拾う
    for (const m of s.matchAll(/\son[a-z]+="([^"]*\$\{[^"]*)"/g)) {
      const line = s.slice(0, m.index).split('\n').length;
      for (const it of m[1].matchAll(/\$\{([^}]{1,120})\}/g)) {
        const e = it[1].trim();
        // 定数・数値・自前で組んだ断片は対象外（値を埋めるものだけ見る）
        if (/^jsAttr\s*\(/.test(e)) continue;
        // クォートで囲んでいない数値・真偽の埋め込みは許す
        if (/^[A-Za-z_$][\w.$]*$/.test(e) && !/\besc\b/.test(e)) { bad.push(`${f}:${line} ${e} （素の差し込み）`); continue; }
        if (/\besc\s*\(/.test(e)) bad.push(`${f}:${line} ${e.slice(0, 70)} （HTML エスケープでは JS 文字列を守れない）`);
      }
    }
  }
  assert.deepEqual(bad, [], 'on* 属性は jsAttr() を使う');
});
