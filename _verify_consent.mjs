import { serve } from '@hono/node-server';
import { createApp, createVerifierApp } from './src/app.mjs';
import { createWalletApp } from './src/wallet-app.mjs';
import { chromium } from 'playwright';
const dir='/private/tmp/claude-501/-Users-kthrtty-Documents-workspace-ihv-eudi-jp/f75bb6d9-a2f8-411a-95c6-7f8e57b7729c/scratchpad';
const IP=8990,VP=8991,WP=8992;
const ISSUER=`http://127.0.0.1:${IP}`,VERIF=`http://127.0.0.1:${VP}`,WALLET=`http://127.0.0.1:${WP}`;
const cookieOf=(r)=>r.headers.get('set-cookie')?.split(';')[0];
async function driveAdd(app,res,cookie){cookie=cookie||cookieOf(res);let last=null;for(let i=0;i<20;i++){last=await (await app.request('/add/step',{method:'POST',headers:{cookie}})).json();if(!last.ok||last.finished)break;}return cookie;}
const issuer=serve({fetch:createApp({credentialIssuer:ISSUER}).fetch,port:IP});
const verifier=serve({fetch:createVerifierApp({verifierOrigin:VERIF,walletOrigin:WALLET,issuerUrl:ISSUER}).fetch,port:VP});
const wallet=createWalletApp({walletOrigin:WALLET,issuerUrl:ISSUER});
const wsrv=serve({fetch:wallet.fetch,port:WP});
await new Promise(r=>setTimeout(r,300));
try{
  // issue pid_mdoc twice into same wallet session (2 matches)
  let cookie=null;
  for(let k=0;k<2;k++){
    const made=await (await fetch(`${ISSUER}/offer`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential_configuration_ids:['pid_mdoc']})})).json();
    const add=await wallet.request('/add?credential_offer_uri='+encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`),cookie?{headers:{cookie}}:{});
    cookie=await driveAdd(wallet,add,cookie||cookieOf(add));
  }
  // find issuance indices, revoke the SECOND one
  const iss=(await (await fetch(`${ISSUER}/issuances`)).json()).issuances;
  const idx=iss[iss.length-1].idx;
  await fetch(`${ISSUER}/revoke`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({index:idx,reason:'test'})});
  console.log('revoked idx',idx,'of',iss.map(e=>e.idx));
  // build presentation request
  const build=await (await fetch(`${VERIF}/vp/build`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({configId:'pid_mdoc',claims:['family_name','given_name'],protocol:'annex-d',target:'web'})})).json();
  const reqUri=new URL(build.walletPresent).searchParams.get('request_uri');
  const [cname,cval]=cookie.split('=');
  const b=await chromium.launch();
  const ctx=await b.newContext({viewport:{width:560,height:1000},deviceScaleFactor:2});
  await ctx.addCookies([{name:cname,value:cval,domain:'127.0.0.1',path:'/'}]);
  const p=await ctx.newPage();
  await p.goto(WALLET+'/present?request_uri='+encodeURIComponent(reqUri),{waitUntil:'networkidle'});
  await p.waitForTimeout(400);
  await p.screenshot({path:dir+'/consent-live-1.png',fullPage:true,animations:'disabled'});
  // status chips present?
  const chips=await p.$$eval('.prow .sc',els=>els.map(e=>e.textContent.trim()));
  console.log('CANDIDATE_CHIPS',JSON.stringify(chips));
  // select the revoked (2nd) radio -> peek should turn red + warning
  const radios=await p.$$('input[name^="cred:"]');
  await radios[1].click();
  await p.waitForTimeout(300);
  const peekState=await p.$eval('#vpeek .vst',e=>e.className+' | '+e.textContent.trim());
  const warnShown=await p.$eval('#peekWarn',e=>!e.hidden).catch(()=>false);
  console.log('PEEK_AFTER_SELECT_REVOKED',peekState,'WARN',warnShown);
  await p.screenshot({path:dir+'/consent-live-2.png',fullPage:true,animations:'disabled'});
  await b.close();
}catch(e){console.error('ERR',e.stack||e.message);}
finally{issuer.close();verifier.close();wsrv.close();}
