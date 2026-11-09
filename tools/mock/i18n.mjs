import {readFileSync} from 'node:fs';
import {chromium} from 'playwright';
const BASE = process.env.MEDUSA_UI_URL || 'http://localhost:8000/';
const MOCK = BASE + '?mock=1';

const b = await chromium.launch();
const ctx = await b.newContext({viewport:{width:1400,height:1000},deviceScaleFactor:1});
const p = await ctx.newPage();
let fails=0; const ok=(c,m)=>{console.log((c?'PASS  ':'FAIL  ')+m); if(!c)fails++;};

await p.goto(MOCK);
await p.evaluate(()=>localStorage.clear());
await p.reload(); await p.waitForTimeout(900);

const nav = async () => (await p.locator('#nav a').allInnerTexts()).map(s=>s.trim());
ok((await nav()).includes('Настройки'), 'RU по умолчанию: ' + (await nav()).join(', '));

/* ---- подвал: GitHub выше разделительной полосы, кнопка языка справа от версии ---- */
const rep = await p.locator('.repolink').boundingBox();
const foot = await p.locator('.foot').boundingBox();
const langBtn = await p.locator('#langBtn').boundingBox();
const mode = await p.locator('#mode').boundingBox();
ok(Math.abs(rep.y - langBtn.y) < 6, `GitHub и переключатель языка в одном ряду (y=${Math.round(rep.y)} и y=${Math.round(langBtn.y)})`);
ok(Math.abs(rep.height - langBtn.height) < 2, `одинаковая высота кнопок (${Math.round(rep.height)} и ${Math.round(langBtn.height)})`);
ok(langBtn.x > rep.x + rep.width, `переключатель справа от GitHub (x=${Math.round(langBtn.x)} против x=${Math.round(rep.x+rep.width)})`);
ok(rep.y + rep.height <= foot.y + 2 && langBtn.y + langBtn.height <= foot.y + 2, `обе кнопки над разделительной полосой (полоса y=${Math.round(foot.y)})`);
ok((await p.locator('#mode').innerText()) === 'Версия панели — 0.1.0', 'подпись версии: ' + await p.locator('#mode').innerText());
ok((await p.locator('#langCode').innerText()) === 'RU', 'кнопка показывает текущий язык: RU');

/* ---- карточки сервера: без аптайма и без «12 ядер», время чч:мм ---- */
const cards = (await p.locator('#sysgrid .syscard').allInnerTexts());
ok(cards.length === 3, 'карточек сервера (ЦП/ОЗУ/диск) = ' + cards.length);
ok(!cards.some(c=>/аптайм|uptime/i.test(c)), 'карточки «Аптайм» больше нет');
ok(!/ядер|cores/i.test(cards[0]), 'рядом с занятостью ЦП нет подписки про ядра: ' + cards[0].replace(/\n/g,' | '));
const stamp = await p.locator('#sysnote').innerText();
ok(/\d{2}:\d{2}$/.test(stamp.trim()), 'время в формате чч:мм: ' + stamp);

/* ---- переключение на английский ---- */
await p.click('#langBtn');
await p.waitForTimeout(600);
const navEn = await nav();
ok(navEn.includes('Settings') && navEn.includes('Overview'), 'меню на английском: ' + navEn.join(', '));
ok((await p.locator('#langCode').innerText()) === 'EN', 'после переключения кнопка показывает EN');
ok((await p.locator('#langBtn').evaluate(el=>el.title)) !== '', 'у кнопки есть подсказка: ' + await p.locator('#langBtn').evaluate(el=>el.title));
ok((await p.locator('#mode').innerText()) === 'Panel version — 0.1.0', 'подпись версии на английском: ' + await p.locator('#mode').innerText());
ok((await p.getAttribute('html','lang')) === 'en', '<html lang="en">');
const sysCards = (await p.locator('#sysgrid .syscard').allInnerTexts()).map(s=>s.toLowerCase());
ok(sysCards[0].includes('cpu') && sysCards[1].includes('ram') && sysCards[2].includes('disk'), 'метрики сервера по-английски: ' + sysCards.map(s=>s.split('\n')[0]).join(', '));
for (const pageName of ['users','chains','settings','admins','hosts']) {
  await p.click(`a[data-p="${pageName}"]`); await p.waitForTimeout(350);
  const h = (await p.locator('.head h2').innerText()).trim();
  ok(h === {users:'Users',chains:'Chains',settings:'Settings',admins:'Administrators',hosts:'Hosts'}[pageName], `страница ${pageName}: заголовок «${h}»`);
}
await p.click('a[data-p="overview"]'); await p.waitForTimeout(500);
const titles = (await p.locator('.grp .sect h3').allInnerTexts()).map(x=>x.replace(/\s+/g,' '));
ok(titles.some(x=>/client apps/i.test(x)), 'блок клиентов по-английски: ' + titles.join(' || '));
const donut = await p.locator('.donutmid').innerText();
ok(/subscription/i.test(donut), 'подпись в центре кольца по-английски: ' + donut.replace(/\s+/g,' '));
const kinds = await p.evaluate(()=>[...document.querySelectorAll('#view section.grp')].map(s=>s.querySelector('#sysgrid') ? 'сервер' : s.querySelector('.flow') ? 'ноды' : s.querySelector('.clients') ? 'клиенты' : '?'));
ok(kinds.join(' → ') === 'сервер → ноды → клиенты', 'порядок блоков на обзоре: ' + kinds.join(' → '));
const flowTitle = (await p.locator('.grp .sect h3').nth(1).innerText()).replace(/\s+/g,' ');
ok(/traffic per node/i.test(flowTitle), 'блок статистики нод по-английски: ' + flowTitle);
const flowRow = (await p.locator('.flowrow').first().innerText()).toLowerCase().replace(/\s+/g,' ');
ok(/of total/.test(flowRow), 'доля трафика по-английски: ' + flowRow);
await p.click('a[data-p="chains"]'); await p.waitForTimeout(350);
const chainText = (await p.locator('.chain .meta').first().innerText()).replace(/\s+/g,' ');
ok(/hop/.test(chainText), 'хопы по-английски: ' + chainText);
await p.click('a[data-p="settings"]'); await p.waitForTimeout(350);
const themeOption = await p.locator('select[name="theme"] option[selected]').innerText();
ok(themeOption === 'Follow system', 'опция темы по-английски: ' + themeOption);
ok((await p.locator('.sh').allInnerTexts()).map(s=>s.trim()).join(', ').includes('Security'), 'секции настроек по-английски: ' + (await p.locator('.sh').allInnerTexts()).map(s=>s.trim()).join(', '));

/* ---- язык переживает перезагрузку ---- */
ok(await p.evaluate(()=>JSON.parse(localStorage.getItem('medusa:lang') || 'null')) === 'en', 'язык сохранён в localStorage: ' + await p.evaluate(()=>localStorage.getItem('medusa:lang')));
await p.reload(); await p.waitForTimeout(900);
ok((await nav()).includes('Nodes'), 'после перезагрузки язык тот же: ' + (await nav()).join(', '));
const repEn = await p.locator('.repolink').boundingBox();
ok(repEn.y + repEn.height <= (await p.locator('.foot').boundingBox()).y + 2, 'раскладка не поехала после перезагрузки');

/* ---- тема/настройки по-прежнему работают на английском ---- */
await p.click('a[data-p="settings"]'); await p.waitForTimeout(300);
await p.selectOption('select[name="theme"]', 'dark'); await p.waitForTimeout(400);
ok(await p.getAttribute('html','data-theme') === 'dark', 'тёмная тема применяется');
const store = await p.evaluate(()=>JSON.parse(localStorage.getItem('medusa:settings')||'{}'));
ok(store.theme === 'dark', 'и сохраняется: ' + store.theme);
await p.fill('input[name="panelName"]', 'Hydra'); await p.waitForTimeout(300);
ok(await p.isVisible('#draftFlag'), 'флаг «unsaved»: ' + await p.locator('#draftFlag').innerText());
await p.click('#ssave'); await p.waitForTimeout(400);
const after = await p.evaluate(()=>localStorage.getItem('medusa:settings'));
ok(JSON.parse(after || '{}').panelName === 'Hydra', 'сохранение работает: ' + after);
ok((await p.textContent('#pname')) === 'Hydra', 'название панели обновилось');

/* ---- возвращаем русский ---- */
await p.click('#langBtn'); await p.waitForTimeout(600);
ok((await nav()).includes('Ноды'), 'обратно на русский: ' + (await nav()).join(', '));

/* ---- словарь: ни одной неиспользуемой строки (только чтение файлов, браузер не нужен) ----
   Часть ключей собирается динамически — status.active, role.owner и т. п.; их видно по
   вызовам вида t('status.'+...). Такие префиксы считаем использованием. */
{
  const js = readFileSync('src/panel/static/script.js', 'utf8');
  const html = readFileSync('src/panel/static/index.html', 'utf8');
  const dict = js.slice(js.indexOf('const I18N = {'), js.indexOf('function t(key'));
  const ruPart = dict.slice(dict.indexOf('ru: {'), dict.indexOf('en: {'));
  const keys = [...ruPart.matchAll(/'([a-zA-Z]+\.[A-Za-z]+)'\s*:/g)].map(m => m[1]);
  const used = new Set([...js.matchAll(/t\('([a-zA-Z]+\.[A-Za-z]+)'/g)].map(m => m[1]));
  const prefixes = [...js.matchAll(/t\('([a-zA-Z]+\.)'/g)].map(m => m[1]);
  for (const m of html.matchAll(/data-i18n(?:-[a-z]+)?="([a-zA-Z]+\.[A-Za-z]+)"/g)) used.add(m[1]);
  const dead = keys.filter(k => !used.has(k) && !prefixes.some(pre => k.startsWith(pre)));
  ok(dead.length === 0, `в словаре нет мёртвых строк (ключей ${keys.length})` + (dead.length ? ': ' + dead.join(', ') : ''));
}

await p.screenshot({path:'/tmp/shot/i18n-dark.png'});
await p.reload(); await p.waitForTimeout(800);
await p.screenshot({path:'/tmp/shot/i18n-footer.png'});
await b.close();
console.log(fails?`\n${fails} провалов`:'\nвсе проверки пройдены'); process.exit(fails?1:0);
