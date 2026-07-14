// 主要ページの inline <script> を抽出して構文チェックする回帰テスト。
// 教訓: サーバ側テンプレートリテラル内の正規表現 `\/` はバックスラッシュが消えて
// `/^data:image/(...)/` になり SyntaxError → そのページの JS が全滅する
// （2026-07-14 発覚: 検証ビルダーの形式チップ・JSON生成が全動作不能。混入は f942c64 の
// XSS 修正で追加した IMG_RE。テンプレート内では `\\/` と書く）。構文エラーは
// 「一部の機能が壊れる」でなく「script ブロック全体が死ぬ」ため、ここで一括 pin する。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderVerifyConsole } from '../src/verifier-demo.mjs';
import { renderScenarioHome, renderScenarioRun } from '../src/scenario-demo.mjs';
import { renderVcSelect, groupCatalog } from '../src/authcode-demo.mjs';
import { allConfigIds, configInfo } from '../src/issuer.mjs';
import { scenarioList, getScenario } from '../src/scenarios.mjs';

const scripts = (html) => [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
const checkAll = (name, html) => {
  const list = scripts(html);
  assert.ok(list.length > 0, `${name}: inline script が1つ以上ある`);
  for (const [i, src] of list.entries()) {
    try { new Function(src); } catch (e) {
      assert.fail(`${name}: inline script #${i} が構文エラー: ${e.message}`);
    }
  }
};

test('inline JS 構文: 検証ビルダー（形式チップ/JSON生成の生死に直結）', () => {
  checkAll('verifier builder', renderVerifyConsole(groupCatalog(allConfigIds().map(configInfo))));
});

test('inline JS 構文: issuer 発行カタログ', () => {
  checkAll('issuer catalog', renderVcSelect(null, groupCatalog(allConfigIds().map(configInfo)), { walletOrigin: 'https://w.example.test' }));
});

test('inline JS 構文: シナリオ一覧・シナリオ実行ページ', () => {
  checkAll('scenario home', renderScenarioHome(scenarioList()));
  checkAll('scenario run (marriage)', renderScenarioRun(getScenario('marriage')));
});
