import {chromium} from 'playwright';
const BASE = process.env.MEDUSA_UI_URL || 'http://localhost:8000/';
const MOCK = BASE + '?mock=1';
const b=await chromium.launch();
const ctx=await b.newContext({viewport:{width:1380,height:1100},deviceScaleFactor:1});
const p=await ctx.newPage();
let fails=0; const ok=(c,m)=>{console.log((c?'PASS  ':'FAIL  ')+m); if(!c)fails++;};
await p.goto(MOCK);
await p.evaluate(()=>localStorage.clear()); await p.reload(); await p.waitForTimeout(1200);

// никаких анимированных «квадератиков»/точек рядом с маркерами нод и в бейдже «Онлайн»
const animated = await p.evaluate(()=>{
  const out=[];
  document.querySelectorAll('.flowrow *, .clrow *').forEach(el=>{
    for(const ps of ['', '::before','::after']){
      const cs=getComputedStyle(el,ps);
      if(cs.animationName && cs.animationName!=='none') out.push(`${el.className}${ps}:${cs.animationName}`);
    }
  });
  return out;
});
ok(animated.length === 0, 'в строках нод/клиентов нет ни одной анимации: ' + JSON.stringify(animated));
const badges = await p.locator('.flowrow .badge').allInnerTexts();
const badgePseudo = await p.locator('.flowrow .badge').evaluateAll(els=>els.map(e=>getComputedStyle(e,'::before').content));
ok(badgePseudo.every(c=>c==='none'), 'в бейджах статуса нод точки/псевдоэлемента больше нет: ' + badgePseudo.join(', '));
ok(badges.every(t=>['Онлайн','Недоступна'].includes(t.trim())), 'подписи статуса: ' + badges.join(', '));
const dotSize = await p.locator('.flowrow .fdot').first().evaluate(el=>{const r=el.getBoundingClientRect();return `${Math.round(r.width)}x${Math.round(r.height)}`});
ok(dotSize==='10x10', 'маркер ноды — просто круг ' + dotSize);

// блок клиентов
ok(await p.locator('.clients').count()===1, 'блок «Приложения клиентов» есть');
const segs = await p.locator('.donut .seg').evaluateAll(els=>els.map(e=>({c:e.style.getPropertyValue('--cc'), da:e.getAttribute('stroke-dasharray'), off:e.getAttribute('stroke-dashoffset'), title:e.querySelector('title')?.textContent})));
ok(segs.length===4, 'сегментов кольца: ' + segs.length);
ok(segs.every(s=>s.c.startsWith('hsl')), 'каждый сегмент своего цвета');
ok(segs[0].title.includes('Clash Verge'), 'наведение с подписью: ' + segs.map(s=>s.title).join(' | '));
const mid = await p.locator('.donutmid').innerText();
ok(mid.replace(/\s+/g,' ') === '5 подписок', 'по кольца: ' + mid.replace(/\s+/g,' '));
const rows = await p.locator('.clrow').allInnerTexts();
ok(rows.length===4, 'строк клиентов: ' + rows.length);
ok(rows[0].includes('Clash Verge') && rows[0].includes('2 подписки'), 'первая строка: ' + rows[0].replace(/\n/g,' | '));
ok(rows.some(r=>r.includes('Happ')), 'Happ в списке есть');
const clientsLegend = await p.locator('.grp:has(.clients) .legend .lgd').allInnerTexts();
ok(clientsLegend.length===4, 'легенда клиентов: ' + clientsLegend.join(', '));
const donutBox = await p.locator('.donut').boundingBox();
ok(Math.abs(donutBox.width - donutBox.height) < 2, `кольцо круглое: ${Math.round(donutBox.width)}x${Math.round(donutBox.height)}`);
ok(await p.locator('.clients .badge').first().isVisible(), 'доля подписок показана бейджем: ' + await p.locator('.clients .badge').first().innerText());
ok((await p.locator('#view .grp').count()) === 3, 'на обзоре три блока: сервер, клиенты, ноды');

// в таблице пользователей виден клиент
await p.click('a[data-p="users"]'); await p.waitForTimeout(400);
ok((await p.locator('.who .mono').first().innerText()).includes('Happ'), 'в списке пользователей видно приложение: ' + await p.locator('.who .mono').first().innerText());

await p.click('a[data-p="overview"]'); await p.waitForTimeout(700);
await p.screenshot({path:'/tmp/shot/clients-light.png'});
await p.evaluate(()=>{const s=JSON.parse(localStorage.getItem('medusa:settings')||'{}');s.theme='dark';localStorage.setItem('medusa:settings',JSON.stringify(s));});
await p.reload(); await p.waitForTimeout(1100);
await p.locator('.clients').screenshot({path:'/tmp/shot/clients-dark.png'});
await p.setViewportSize({width:390,height:820}); await p.waitForTimeout(600);
await p.locator('.clients').screenshot({path:'/tmp/shot/clients-mobile.png'});
await b.close();
console.log(fails?`\n${fails} провалов`:'\nвсе проверки пройдены'); process.exit(fails?1:0);
