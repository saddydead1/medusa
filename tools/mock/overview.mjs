import {chromium} from 'playwright';
const BASE = process.env.MEDUSA_UI_URL || 'http://localhost:8000/';
const MOCK = BASE + '?mock=1';

const b = await chromium.launch();
const ctx = await b.newContext({viewport:{width:1380,height:1000},deviceScaleFactor:1});
const p = await ctx.newPage();
let fails=0; const ok=(c,m)=>{console.log((c?'PASS  ':'FAIL  ')+m); if(!c)fails++;};

await p.goto(MOCK);
await p.evaluate(()=>{localStorage.clear();});
await p.reload();
await p.waitForTimeout(900);

const link = p.locator('.repolink');
ok(await link.count()===1, 'кнопка GitHub в подвале сайдбара');
ok((await link.getAttribute('href'))==='https://git.sonoma.su/saddydead1/medusa', 'ссылка ведёт куда надо: ' + await link.getAttribute('href'));
ok((await link.getAttribute('target'))==='_blank', 'открывается в новой вкладке');
const [linkBox, modeBox] = await Promise.all([p.locator('.repolink').boundingBox(), p.locator('#mode').boundingBox()]);
ok(linkBox.y + linkBox.height <= modeBox.y + 2, `GitHub выше версии (y=${Math.round(linkBox.y)} против y=${Math.round(modeBox.y)})`);

ok(await p.locator('#sysgrid .syscard').count() === 3, 'блок «Сервер»: карточек = ' + await p.locator('#sysgrid .syscard').count());
/* тестовый режим бэкенда не трогает: сервер на обзоре — тот, что задуман в моке */
const mockHost = await p.evaluate(() => mockSystem().hostname);
const title = await p.locator('.grp .sect h3').first().innerText();
ok(title.includes('Сервер') && title.includes(mockHost), 'сервер взят из тестовых данных: ' + title.replace(/\s+/g,' '));
const texts = (await p.locator('#sysgrid .syscard').allInnerTexts()).map(x=>x.toLowerCase());
const cpuCard = texts.find(x=>x.includes('цп')), memCard = texts.find(x=>x.includes('озу')), diskCard = texts.find(x=>x.includes('диск'));
ok(!!cpuCard && !/ядер/.test(cpuCard), 'ЦП без подписки про ядра: ' + cpuCard.replace(/\n/g,' | '));
ok(!texts.some(x=>x.includes('аптайм')), 'карточки «Аптайм» нет');
ok(!!memCard && /гб/.test(memCard), 'Память: ' + memCard.replace(/\n/g,' | '));
ok(!!diskCard && /гб/.test(diskCard), 'Диск: ' + diskCard.replace(/\n/g,' | '));
const stamp = (await p.locator('#sysnote').innerText()).trim();
ok(/\d{2}:\d{2}$/.test(stamp), 'живая плашка, время чч:мм: ' + stamp);

const cpuBefore = await p.locator('#sysgrid .syscard').first().innerText();
const barWidths = await p.locator('#sysgrid .bar i').evaluateAll(els=>els.map(e=>e.style.width+'|'+e.className));
ok(barWidths.length>=3 && barWidths.every(w=>/%/.test(w)), 'полоски загрузки: ' + barWidths.join('  '));

/* ---- как выглядит статистика по нодам ---- */
ok(await p.locator('#view table').count() === 0, 'скучной таблицы на обзоре больше нет');
ok(await p.locator('.flowrow').count() === 3, 'строк нод: ' + await p.locator('.flowrow').count());
const segs = await p.locator('.flowbar i').evaluateAll(els=>els.map(e=>({w:e.style.width, c:e.style.getPropertyValue('--nc')})));
ok(segs.length === 3, 'сегментов общей полосы: ' + segs.length);
const sum = segs.reduce((a,x)=>a+parseFloat(x.w), 0);
ok(sum > 99 && sum < 101, 'доли нод в общей полосе sums в ' + sum.toFixed(1) + '%');
ok(new Set(segs.map(x=>x.c)).size === 3, 'каждая нода своего цвета: ' + segs.map(x=>x.c).join(', '));
const rowsTxt = (await p.locator('.flowrow').allInnerTexts()).map(x=>x.toLowerCase().replace(/\s+/g,' '));
ok(rowsTxt.every(x=>/гб/.test(x)), 'в строках есть трафик в ГБ');
ok(rowsTxt.every(x=>/% от общего/.test(x)), 'в строках есть доля от общего трафика');
ok(!rowsTxt.every(x=>/xray/.test(x)), 'версии xray в строках обзора больше нет');
ok(await p.locator('.flowrow .badge').count() === 3, 'у каждой ноды есть индикатор статуса');
const badges = await p.locator('.flowrow .badge').allInnerTexts();
ok(badges.every(b=>['Онлайн','Недоступна'].includes(b.trim())), 'индикаторы состояния нод: ' + badges.join(', '));
ok(await p.locator('.flowrow .badge.b-ok').count() >= 1, 'есть хотя бы одна активная нода');
const dotAnim = await p.locator('.fdot').evaluateAll(els=>els.map(e=>getComputedStyle(e).animationName));
ok(dotAnim.every(a=>a === 'none'), 'с кружочков нод анимацию сняли: ' + dotAnim.join(', '));
const badgeAnim = await p.locator('.flowrow .badge').evaluateAll(els=>els.map(e=>getComputedStyle(e,'::before').animationName));
ok(badgeAnim.every(a=>a === 'none'), 'в бейдже статуса анимации/точки нет: ' + badgeAnim.join(', '));
ok(await p.locator('.flowrow .fdot').count() === 3, 'у каждой ноды свой цветной маркер');
ok((await p.locator('.flowrow').first().evaluate(el=>el.style.getPropertyValue('--nc'))) !== '', 'цвет строки задан: ' + await p.locator('.flowrow').first().evaluate(el=>el.style.getPropertyValue('--nc')));
const widths = await p.locator('.fbar i').evaluateAll(els=>els.map(e=>parseFloat(e.style.width)));
ok(widths.includes(Math.max(...widths)) && Math.max(...widths) > 95, 'самая загруженная нода заполняет полосу на ' + Math.max(...widths) + '%');
const nodesLegend = await p.locator('.grp:has(.flow) .legend .lgd').allInnerTexts();
ok(nodesLegend.length === 3, 'легенда нод на месте: ' + nodesLegend.join(', '));

// автосвежение (интервал из настроек pollInterval): в тестовом режиме панель никуда не ходит,
// но открытую страницу перечитывает сама — считаем перерисовку и отсутствие запросов
let sysReqs = 0;
p.on('request', r=>{ if(r.url().includes('/api/')) sysReqs++; });
await p.evaluate(() => { window.__renders = 0; new MutationObserver(()=>{ window.__renders++; })
  .observe(document.querySelector('#view'), {childList:true, subtree:true}); });
const t1 = await p.locator('#sysnote').innerText();
await p.waitForTimeout(33000);
ok(sysReqs === 0, 'в тестовом режиме панель не делает ни одного запроса к API (запросов за 33 с: ' + sysReqs + ')');
ok(await p.evaluate(() => window.__renders) >= 1, 'страница перерисовалась сама, без кликов');
ok(await p.locator('#sysgrid .syscard').count() === 3, 'после автосвежения карточек всё те же: 3');
ok(await p.locator('#sysnote').innerText() !== '', 'плашка времени жива: ' + await p.locator('#sysnote').innerText());

await p.screenshot({path:'/tmp/shot/sys-light.png'});
await p.evaluate(()=>{const s=JSON.parse(localStorage.getItem('medusa:settings')||'{}');s.theme='dark';localStorage.setItem('medusa:settings',JSON.stringify(s));});
await p.reload(); await p.waitForTimeout(900);
await p.screenshot({path:'/tmp/shot/sys-dark.png', fullPage:false});
await p.setViewportSize({width:390,height:820}); await p.waitForTimeout(500);
await p.screenshot({path:'/tmp/shot/sys-mobile.png'});
await b.close();
console.log(fails?`\n${fails} провалов`:'\nвсе проверки пройдены'); process.exit(fails?1:0);
