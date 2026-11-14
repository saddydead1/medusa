/* Проверка фронтенда против настоящего бэкенда (без мока).

   Запуск:
     .venv/bin/python -m uvicorn src.panel.main:app --port 8000
     node tools/ui_test.mjs                      # playwright лежит в tools/node_modules

   Тест сам вычищает базу и может запускаться сколько угодно раз подряд. */
import {spawn} from 'node:child_process';
import {rm} from 'node:fs/promises';
import {appendFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {readFileSync} from 'node:fs';
import {chromium} from 'playwright';

/* версия ноды = версия проекта (pyproject.toml одна на панель и на ноду),
   поэтому тест не держит её внутри себя числом: правка версии не ломает проверки */
const VERSION = (readFileSync(new URL('../pyproject.toml', import.meta.url), 'utf8')
  .match(/^version = "([^"]+)"/m) || [])[1] || '';

const BASE = (process.env.MEDUSA_UI_URL || 'http://localhost:8000/').replace(/\/+$/, '');
const b = await chromium.launch();
const ctx = await b.newContext({viewport: {width: 1380, height: 900}});
await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
const page = await ctx.newPage();
const errors = [];
page.on('dialog', d => d.accept());          // подтверждения фронтенда принимаем молча
/* 400/401/409 в этом тесте ожидаемые: плохой пароль, панель без сессии, дубликат пользователя */
page.on('console', m => { if(m.type() === 'error' && !/\b(400|401|409)\b/.test(m.text())) errors.push(m.text()); });
page.on('pageerror', e => errors.push('pageerror: ' + e.message));

let fails = 0;
/* В Actions логи шага видны только человеку с правами на репозиторий, поэтому проваленная
   проверка дублируется аннотацией (::error::) и в сводку шага — иначе «упало» ничего не объясняет. */
const annotate = (msg) => {
  const line = msg.replace(/\n/g, ' ').slice(0, 300);
  if(process.env.GITHUB_ACTIONS) console.log(`::error::${line}`);
  if(process.env.GITHUB_STEP_SUMMARY){ try{ appendFileSync(process.env.GITHUB_STEP_SUMMARY, line + '\n'); }catch{ /* сводка не обязательна */ } }
};
const ok = (cond, msg) => { console.log((cond ? 'PASS  ' : 'FAIL  ') + msg); if(!cond){ fails++; annotate('FAIL  ' + msg); } };
/* тест весь построен на верхнем await: невыполненное обещание (например waitForFunction
   не дождался) приходит именно как unhandledRejection, а не как uncaughtException */
const die = (label, err) => {
  const msg = err && err.message ? err.message : String(err);
  console.log('FAIL  ' + label + ': ' + msg);
  annotate('FAIL  ' + label + ': ' + msg);
  process.exit(1);
};
process.on('uncaughtException', e => die('неожиданная ошибка теста', e));
process.on('unhandledRejection', e => die('обещание теста не дождалось', e));
const text = () => page.textContent('#view');
const toastText = () => page.textContent('#toast');
const wait = (fn, arg, opts) => page.waitForFunction(fn, arg, {timeout: 30000, ...(opts || {})});
const closed = sel => wait(x => !document.querySelector(x).open, sel);
/* «timeout» в окне ноды ничего не объясняет: перед тем как упасть, вытаскиваем то,
   что реально стоит в статусе, тосте и версии ноды */
const orDump = async (what, fail, sel = '#ne_status') => {
  try { return await what(); } catch (err) {
    const grab = async s => { const el = await page.$(s); return el ? (await el.textContent()).trim() : '(нет элемента)'; };
    throw new Error(`${fail}: ${err.message} | ${sel}=${await grab(sel)} | toast=${await grab('#toast')} | agent=${await grab('#ne_agent')}`);
  }
};
const go = async (tab) => {
  await page.click(`#nav a[data-p="${tab}"]`);
  // дожидаемся не «изменения HTML», а именно отрендеренной страницы: иначе можно
  // остаться на прежней странице и считать карточки там, где их нет
  await page.waitForFunction(t => document.querySelector('#view').dataset.page === t, tab);
};
const clearToast = () => page.evaluate(() => { const e = document.querySelector('#toast'); e.classList.remove('show'); e.textContent = ''; });
/* ждём, пока карточка ноды покажет нужное (имя + подстроку): предикат живёт на странице,
   поэтому данные передаём аргументом, а не замыканием */
const cardShows = (name, text) => page.waitForFunction(([n, sub]) => [...document.querySelectorAll('#view .node')]
  .some(x => x.textContent.includes(n) && x.textContent.includes(sub)), [name, text], {timeout: 90000});

/* вторая тестовая нода: тот же самый код, другой порт, другой API-ключ и своё состояние */
const freePort = () => new Promise(resolve => {
  const srv = createServer();
  srv.listen(0, '127.0.0.1', () => { const port = srv.address().port; srv.close(() => resolve(port)); });
});
async function spawnNode(port, apiKey, stateFile){
  const proc = spawn('.venv/bin/python', ['-m', 'uvicorn', 'src.node.main:app', '--host', '127.0.0.1', '--port', String(port)],
    {env: {...process.env, MEDUSA_NODE_API_KEY: apiKey, MEDUSA_NODE_PORT: String(port), MEDUSA_NODE_STATE: stateFile}, stdio: 'ignore'});
  for (let i = 0; i < 160; i++) {
    try { if ((await fetch(`http://127.0.0.1:${port}/node/health`)).ok) return proc; } catch { /* ещё не поднялась */ }
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('вторая тестовая нода не поднялась');
}
const stopNode = proc => new Promise(resolve => { proc.once('exit', resolve); proc.kill('SIGTERM'); });
/* учётка владельца: панель теперь без сессии не работает, поэтому тест входит сам */
const OWNER = {username: process.env.MEDUSA_ADMIN_USER || 'admin', password: process.env.MEDUSA_ADMIN_PASSWORD || 'testpass12345'};
const api = async (path, method = 'GET', body = undefined, token = ownerToken) => {
  const r = await fetch(BASE + path, {method, headers: {'content-type': 'application/json', ...(token ? {authorization: `Bearer ${token}`} : {})},
    body: body === undefined ? undefined : JSON.stringify(body)});
  return r;
};
const loginRes = await api('/api/login', 'POST', OWNER, null);
if (!loginRes.ok) throw new Error(`тест не смог войти под владельцем: ${loginRes.status} ${await loginRes.text()}`);
const ownerToken = (await loginRes.json()).token;
async function panelPatch(body){
  const r = await api('/api/settings', 'PATCH', body);
  if (!r.ok) throw new Error(`настройки не сохранились: ${r.status}`);
}
const openDlg = async sel => { await page.waitForSelector(`${sel}[open]`); };
const submit = async (sel, expectToast) => {
  await page.click(`${sel} .btn.pri`);
  await closed(sel);
  if(expectToast) await wait(() => document.querySelector('#toast').classList.contains('show'));
};
const fill = async (dlg, values) => page.evaluate(([d, v]) => {
  const box = document.querySelector(d);
  for(const [k, val] of Object.entries(v)){
    const el = box.querySelector(`[data-f="${k}"]`) || box.querySelector(`[name="${k}"]`);
    el.value = val; el.dispatchEvent(new Event('input', {bubbles: true}));
  }
}, [dlg, values]);

/* тест сам вычищает базу: запускается сколько угодно раз подряд */
const wipe = async () => {
  for(const x of await (await api('/api/chains')).json()) await api('/api/chains/' + x.id, 'DELETE');
  for(const x of await (await api('/api/hosts')).json()) if(!x.chain) await api('/api/hosts/' + x.id, 'DELETE');
  for(const x of await (await api('/api/nodes')).json()) await api('/api/nodes/' + x.id, 'DELETE');
  for(const x of await (await api('/api/users')).json()) await api('/api/users/' + x.id, 'DELETE');
  for(const x of await (await api('/api/admins')).json()) if(x.role !== 'owner') await api('/api/admins/' + x.id, 'DELETE');
  await api('/api/settings', 'PATCH', {panelName: 'Medusa', theme: 'auto', pollInterval: 30, sessionHours: 24, passkeyEnabled: false});
  await page.goto(BASE);
  await page.evaluate(() => localStorage.clear());        // браузер тоже начинается заново: с окна входа
};
await wipe();

/* ---------- окно входа: без учётки панель закрыта, плохой пароль объясняет отказ ---------- */
await page.goto(BASE);
await openDlg('#logdlg');
ok(await page.evaluate(() => !document.querySelector('#view').textContent.trim()), 'без учётки панель не показывает ничего');
ok(await page.evaluate(() => document.querySelector('#logdlg').open), 'панель сама попросила войти');
await page.fill('#lform [name="username"]', OWNER.username);
await page.fill('#lform [name="password"]', 'sovershenno-neTot');
await page.click('#lform .btn.pri');
await page.waitForTimeout(500);
ok(await page.evaluate(() => document.querySelector('#logdlg').open), 'плохой пароль: окно входа осталось открытым');
ok((await page.textContent('#logerr')).length > 0, `панель объяснила плохой вход: ${(await page.textContent('#logerr')).trim()}`);
await page.fill('#lform [name="password"]', OWNER.password);
await page.click('#lform .btn.pri');
await closed('#logdlg');
await page.waitForSelector('#view .syscard');
await page.screenshot({path: '/tmp/shot/01-login.png'});
ok((await page.textContent('#acctname')).trim() === OWNER.username, `сайдбар показывает учётку: ${OWNER.username}`);
ok((await page.textContent('#acctrole')).includes('Владелец'), `и её роль: ${(await page.textContent('#acctrole')).trim()}`);
{
  const box = sel => page.evaluate(x => { const r = document.querySelector(x).getBoundingClientRect();
    return {x:r.x, y:r.y, left:r.left, top:r.top, w:r.width, h:r.height, right:r.right, bottom:r.bottom, mid:r.y + r.height/2}; }, sel);
  const acct = await box('#acct'), name = await box('#acctname'), role = await box('#acctrole'), aside = await box('aside');
  const version = await box('#mode'), repo = await box('.foottop');
  ok(acct.right <= aside.right && acct.left >= aside.left, 'учётка — в сайдбаре');
  ok(acct.y >= repo.bottom - 2 && acct.bottom <= version.y + 2,
     'и стоит ровно между рядом GitHub/язык и строкой версии панели');
  ok(Math.abs(name.x - role.x) < 1, 'ник и роль стоят ровно друг под другом, не съезжают');
  ok(name.bottom <= role.top + 1, 'ник и роль — на разных строках');
  ok(role.right <= acct.right && name.right <= role.x + 220, 'и в границах карточки');
  await page.screenshot({path: '/tmp/shot/00-acct.png'});
}

/* ---------- обзор на живых данных ---------- */
ok((await page.textContent('#pname')).trim() === 'Medusa', 'панель загрузилась без мока');
ok((await text()).includes('Не удалось загрузить') === false, 'данные взял бэкенд, а не мок');
/* карточка диска на «Обзоре» одна: панель показывает основной раздел машины, а не все
   монтирования (/, /home, /boot, снапшоты, overlay контейнеров). Вторая карточка возможна
   только если база панели реально лежит на другом устройстве. */
const sysTitles = await page.evaluate(() => [...document.querySelectorAll('#view .syscard .systitle')]
  .map(x => x.textContent.trim()));
const diskCards = sysTitles.filter(x => /Диск/.test(x));
ok(sysTitles.length >= 3 && sysTitles.some(x => /ЦП/.test(x)) && sysTitles.some(x => /ОЗУ/.test(x))
   && diskCards.length >= 1,
   `блок сервера: ЦП, память и диски с живых метрик: ${sysTitles.join(' | ')}`);
ok(diskCards.length <= 2, `дисков показано не больше основного (и базы панели, если она на другом устройстве): ${diskCards.join(' | ')}`);
ok(!diskCards.some(x => /\/(boot|home|snap|var|mnt)\b/.test(x)),
   `случайных разделов в блоке нет: ${diskCards.join(' | ')}`);
const cpu = (await page.locator('.syscard .sysval').first().textContent()).trim();
ok(/%$/.test(cpu), `ЦП с живых метрик: ${cpu}`);
ok((await page.evaluate(() => savedSettings.panelName)) === 'Medusa', 'настройки пришли с бэкенда');
ok(await page.locator('#view .empty').count() > 0, 'пустая база — пустые состояния на месте');

/* ---------- ноды ---------- */
await go('nodes');
const openCard = async (name) => {
  await page.click(`#view .node:has-text("${name}")`);
  await page.waitForSelector('#nedlg[open]');
};
for (const [i, [name, address]] of [['home', '10.8.0.1'], ['vps-fi', '195.232.115.27']].entries()) {
  await page.click('[data-a="newnode"]');
  await openDlg('#ndlg');
  await fill('#ndlg', {name, address, apiKey: `sk-api-uitest-${name}-00000`});
  await submit('#nform');
  await wait(n => document.querySelectorAll('#view .node').length === n, i + 1);
}
const nodeText = await text();
ok(nodeText.includes('10.8.0.1') && nodeText.includes('195.232.115.27'), 'ноды созданы через API');
ok(nodeText.includes('неизвестно'), 'карточка не выдумывает версии: неизвестно');
ok(!(await page.locator('#view .node').first().textContent()).includes('sk-api'), 'карточка ноды не показывает API-ключ');
ok(!(await page.locator('#view .node').first().textContent()).includes('/node/health'), 'карточка ноды не показывает её API');
ok(!(await page.locator('#view .node').first().textContent()).includes('ещё не проверялась'), 'карточки не забиты состоянием связи');
ok(await page.locator('#ndlg [data-f="apiKey"]').evaluate(el => el.required), 'без API-ключа ноду не добавить');

/* ---------- IPv6 на ноде: галочка, её границы и обратный ход ---------- */
await page.click('[data-a="newnode"]');
await openDlg('#ndlg');
await fill('#ndlg', {name: 'nov6', address: '10.8.0.7', apiKey: 'sk-api-uitest-nov6-0000000'});
await page.check('#nform [data-f="ipv6Disabled"]');
await submit('#nform');
await wait(n => document.querySelectorAll('#view .node').length === n, 3);
const v6row = (await (await api('/api/nodes')).json()).find(x => x.name === 'nov6');
ok(v6row && v6row.ipv6Disabled === true, 'галочка «выключить IPv6» доехала до базы');
await openCard('nov6');
ok(await page.isChecked('#nedlg [data-f="ipv6Disabled"]'), 'окно правки предзаполняет выключенный IPv6');
await page.click('#nedlg button[value="cancel"]');
await closed('#nedlg');
await page.waitForTimeout(200);
const badHost = await api('/api/hosts', 'POST', {name: 'v6-host', node: 'nov6', protocol: 'vless', port: 8443, address: '2001:db8::7'});
const badText = (await badHost.json()).detail;
ok(badHost.status === 400 && badText.includes('IPv6'), `хост с IPv6-адресом на такой ноде отвергнут: ${badText}`);
ok(await api('/api/nodes/' + v6row.id, 'DELETE').then(r => r.status) === 204, 'тестовую ноду без IPv6 убрали');
await go('overview'); await go('nodes');
await wait(() => document.querySelectorAll('#view .node').length === 2, null, {timeout: 60000});

/* ---------- связка с живой нодой: отдельный порт и API-ключ ноды ---------- */
const nodePort = process.env.MEDUSA_TEST_NODE_PORT;
const nodeKey = process.env.MEDUSA_TEST_NODE_KEY;
if (nodePort && nodeKey) {
  await page.click('[data-a="newnode"]');
  await openDlg('#ndlg');
  await fill('#ndlg', {name: 'live', address: '127.0.0.1', apiPort: nodePort, apiKey: nodeKey});
  await submit('#nform');
  await wait(n => document.querySelectorAll('#view .node').length === n, 3);
  ok((await page.locator('#view .node', {hasText: 'live'}).textContent()).includes(`127.0.0.1:${nodePort}`),
     'карточка показала адрес ноды и её порт API');

  await openCard('live');
  const fp = (await page.textContent('#ne_key')).match(/[a-z0-9]{5}-[a-z0-9]{5}/);
  ok(fp, `в окне виден отпечаток API-ключа: ${fp ? fp[0] : await page.textContent('#ne_key')}`);
  ok((await page.inputValue('#nedlg [data-f="apiKey"]')) === nodeKey,
     'поле API-ключа заполнено настоящим ключом — как адрес и порт');
  ok((await page.textContent('#ne_seen')).includes('ещё не проверялась'), 'связь ещё не проверялась');
  ok((await page.textContent('#ne_badge')).trim() === 'Недоступна', 'в окне тот же статус, что на карточке');

  await page.click('#nedlg [data-a="ncheck"]');
  await orDump(() => page.waitForFunction(() => !document.querySelector('#ne_status').hidden, null, {timeout: 60000}),
               'панель не показала результат проверки связи');
  ok((await page.textContent('#ne_status')).includes('API-ключ подходит'),
     `живая проверка связи: ${await page.textContent('#ne_status')}`);
  ok((await page.textContent('#ne_agent')).includes(VERSION), `нода сообщила версию своего агента (${VERSION})`);
  const trafficTxt = (await page.textContent('#ne_traffic')).trim();
  ok(trafficTxt && /МБ|ГБ/.test(trafficTxt) && !trafficTxt.includes('node.traffic'),
     `в окне ноды есть строка её трафика — панель уже забрала счётчики живой ноды: ${trafficTxt}`);
  await page.waitForFunction(() => !document.querySelector('#ne_seen').textContent.includes('ещё не проверялась'), null, {timeout: 60000});
  await orDump(() => wait(x => document.querySelector('#ne_badge').textContent === 'Онлайн'),
               'нода не стала «Онлайн» после проверки связи', '#ne_badge');
  const seen = (await page.textContent('#ne_seen')).toLowerCase();
  ok(seen.includes('назад') || seen.includes('только что'), `в окне видно, когда проверяли связь: ${seen}`);

  await page.click('#nedlg [value="cancel"]');
  await closed('#nedlg');
  await wait(() => {
    const el = [...document.querySelectorAll('#view .node')].find(x => x.textContent.includes('live'));
    return !!el && el.textContent.includes('Онлайн');
  });
  const live = await page.locator('#view .node', {hasText: 'live'}).textContent();
  ok(live.includes('Онлайн'), 'нода сама сообщила, что она в сети');
  ok(live.includes(VERSION), `версия ноды появилась на карточке (${VERSION})`);

  /* меняем API-ключ на чужой: нода отвечает, но работать с ней нельзя */
  await openCard('live');
  await fill('#nedlg', {apiKey: 'sk-api-uitest-wrong-00000000'});
  clearToast();
  await submit('#neform');
  await wait(() => document.querySelector('#toast').textContent.includes('нода обновлена'));
  ok(true, `ключ заменён: ${await toastText()}`);
  await openCard('live');
  await page.click('#nedlg [data-a="ncheck"]');
  await page.waitForFunction(() => document.querySelector('#ne_status').classList.contains('bad'));
  ok((await page.textContent('#ne_status')).includes('не подходит'),
     `чужой API-ключ отвергнут: ${await page.textContent('#ne_status')}`);
  await page.click('#nedlg [value="cancel"]');
  await closed('#nedlg');
  ok((await page.locator('#view .node', {hasText: 'live'}).textContent()).includes('Недоступна'),
     'нода с не тем API-ключом осталась не в сети');

  /* и снова вернули правильный */
  await openCard('live');
  await fill('#nedlg', {apiKey: nodeKey});
  await submit('#neform');
  await openCard('live');
  await page.click('#nedlg [data-a="ncheck"]');
  await page.waitForFunction(() => !document.querySelector('#ne_status').hidden);
  ok((await page.textContent('#ne_status')).includes('API-ключ подходит'), 'правильный ключ — связь снова есть');
  await page.click('#nedlg [value="cancel"]');
  await closed('#nedlg');

  /* имя ноды — дело панели: связь оно не должно трогать */
  await openCard('live');
  await fill('#nedlg', {name: 'live-2'});
  ok((await page.textContent('#ne_name')).trim() === 'live',
     'пока правку не сохранили, заголовок окна остаётся прежним');
  clearToast();
  await submit('#neform');
  await wait(() => document.querySelector('#toast').textContent.includes('нода обновлена'));
  await wait(() => !!document.querySelector(`#view .node[data-id][role="button"]`) &&
                  [...document.querySelectorAll('#view .node')].some(x => x.textContent.includes('live-2')));
  const renamed = await page.locator('#view .node', {hasText: 'live-2'}).textContent();
  ok(renamed.includes('Онлайн'), `переименовали — и нода осталась в сети: ${renamed.replace(/\s+/g, ' ')}`);
  /* ---------- статус ноды обновляется сам ----------
     Панель опрашивает ноды по таймеру, открытая страница перечитывается с тем же
     интервалом. Здесь проверка честная: никто не нажимает «Проверить связь» и не
     перезагружает страницу — меняется только сама нода. */
  await panelPatch({pollInterval: 6, nodeTimeout: 2});
  await page.reload();
  await go('nodes');

  const pollPort = await freePort();
  const pollState = `${process.env.MEDUSA_NODE_STATE || '/tmp'}.poll.json`;
  const pollKey = 'sk-api-pollnode000000000000001';
  await rm(pollState, {force: true});
  let pollProc = await spawnNode(pollPort, pollKey, pollState);

  await page.click('[data-a="newnode"]');
  await openDlg('#ndlg');
  await fill('#ndlg', {name: 'pollnode', address: '127.0.0.1', apiPort: pollPort, apiKey: pollKey});
  await submit('#nform');
  /* считаем не «сколько карточек вообще» (страница в этот момент может перерисовываться),
     а наличие нужной ноды */
  await wait(() => [...document.querySelectorAll('#view .node')].some(x => x.textContent.includes('pollnode')));

  await cardShows('pollnode', 'Онлайн');
  const polled = (await page.locator('#view .node', {hasText: 'pollnode'}).textContent()).replace(/\s+/g, ' ');
  ok(polled.includes('Онлайн') && polled.includes(VERSION),
     `нода в сети сама, без кнопки и перезагрузки: ${polled}`);

  /* нода перезапустилась с другим API-ключом: панель обязана увидеть это сама */
  await stopNode(pollProc);
  await rm(pollState, {force: true});
  pollProc = await spawnNode(pollPort, 'sk-api-pollnodeOTHER00000000002', pollState);
  await cardShows('pollnode', 'Недоступна');
  ok(true, 'нода сменила API-ключ — и стала недоступной без единого клика');

  /* ---------- socks5: панель доходит до ноды через прокси ----------
     Нода может сидеть за NAT или быть доступна только через прыжок. Проверка настоящая:
     поднят свой socks5-сервер, прокси вписан в окно ноды как это делает человек, и панель
     продолжает ходить к ноде — уже через него. */
  const socks = spawn('.venv/bin/python', ['tools/socks5.py', 'medusa', 'sockssecret'],
    {stdio: ['ignore', 'pipe', 'ignore']});
  const socksUrl = await new Promise((resolve, reject) => {
    socks.stdout.on('data', d => { const s = d.toString().trim(); if (s.includes('socks5://')) resolve(s); });
    setTimeout(() => reject(new Error('socks5-прокси не назвал свой адрес')), 12000);
  });
  ok(socksUrl.startsWith('socks5://medusa'), `подняли настоящий socks5-прокси: ${socksUrl.replace('sockssecret', '••••')}`);

  await openCard('pollnode');
  await fill('#nedlg', {proxy: socksUrl});
  await submit('#neform');
  await wait(() => document.querySelector('#toast').textContent.includes('нода обновлена'));

  await openCard('pollnode');
  ok((await page.inputValue('#nedlg [data-f="proxy"]')) === socksUrl,
     'окно правки предзаполняет прокси целиком, с паролем: masked-форма для сохранения не годится');
  ok(await page.evaluate(() => !document.querySelector('#ne_proxy') &&
      !/панель идёт к этой ноде/.test(document.querySelector('#nedlg').textContent)),
     'под полем SOCKS5-прокси текста нет: окно ноды не печатает строку «как именно идём»');
  await page.click('#nedlg [data-a="ncheck"]');
  /* ключ этой ноды тест уже сменил (проверка «статус обновляется сам»), поэтому связка
     не обязана складываться. Важное здесь другое: нода ОТВЕТИЛА через прокси и отвергла
     не тот ключ — значит путь работал. Не работала бы socks5-дорога, панель виноватым
     назвала бы прокси. */
  await wait(() => document.querySelector('#ne_status').textContent.includes('Связь не сложилась'));
  const viaCheck = (await page.textContent('#ne_status')).trim();
  ok(viaCheck.includes('не подходит'),
     `панель дошла до ноды через socks5: нода ответила и отвергла ключ — ${viaCheck}`);

  socks.kill('SIGTERM');
  await page.waitForTimeout(1500);            // прокси должен успеть умереть
  await page.click('#nedlg [data-a="ncheck"]');
  await wait(() => document.querySelector('#ne_status').textContent.includes('прокси'), null, {timeout: 25000});
  const brokenCheck = (await page.textContent('#ne_status')).trim().replace('sockssecret', '••••');
  ok(brokenCheck.includes('не ответил') || brokenCheck.includes('не пустил'),
     `если socks5 встал, панель винит socks5, а не Xray на ноде: ${brokenCheck}`);

  const rows = await (await api('/api/nodes')).json();
  const proxied = rows.find(n => n.name === 'pollnode');
  ok(proxied.proxySet === true && proxied.proxy.includes('••••') && !JSON.stringify(rows).includes('sockssecret'),
     `в списке нод пароль прокси скрыт: ${proxied.proxy}`);

  await fill('#nedlg', {proxy: ''});
  await submit('#neform');
  /* PATCH в закрытии диалога асинхронный: читаем список, пока панель не сохранит правку */
  let directRow = null;
  for (let i = 0; i < 60; i++) {
    directRow = (await (await api('/api/nodes')).json()).find(n => n.name === 'pollnode');
    if (directRow && directRow.proxy === '' && directRow.proxySet === false) break;
    await page.waitForTimeout(250);
  }
  ok(directRow && directRow.proxy === '' && directRow.proxySet === false,
     'прокси убран из окна — нода снова ходит напрямую');

  await openCard('pollnode');
  await page.click('#nedlg [data-a="ndelete"]');
  await closed('#nedlg');
  await stopNode(pollProc);
  await rm(pollState, {force: true});
  await panelPatch({pollInterval: 30, nodeTimeout: 10});
} else {
  console.log('SKIP  связка с нодой в UI: MEDUSA_TEST_NODE_PORT / MEDUSA_TEST_NODE_KEY не заданы');
}

/* ---------- пользователи: имя и приложение клиента ---------- */
await go('users');
for(const [name, app] of [['vasya', 'v2rayNG'], ['petya', 'Foxv2ray']]){
  await page.click('[data-a="new"]');
  await openDlg('#dlg');
  await fill('#dlg', {name, client: app});
  await submit('#uform');
  await wait(n => document.querySelector('#view').textContent.includes(n), name);
}
ok((await text()).includes('vasya') && (await text()).includes('petya'), 'пользователи созданы');
ok((await text()).includes('v2rayNG') && (await text()).includes('Foxv2ray'),
   'приложение клиента подписано в строке: и готовое из подсказок, и названное человеком');
clearToast();
await page.click('[data-a="new"]');
await openDlg('#dlg');
await fill('#dlg', {name: 'vasya'});
await submit('#uform', true);
ok((await toastText()).includes('уже есть'), `текст об ошибке пришёл с бэкенда: ${await toastText()}`);

/* правка пользователя: приложение меняется, и панель отдаёт его обратно */
clearToast();
await page.click(`#view tr:has-text("petya") [data-a="uedit"]`);
await openDlg('#uedlg');
ok(await page.inputValue('#ueclient') === 'Foxv2ray',
   `диалог правки предзаполнен и своё приложение не потеряно: ${await page.inputValue('#ueclient')}`);
await fill('#uedlg', {client: 'hiddify'});
await submit('#ueform');
await wait(() => document.querySelector('#view').textContent.includes('Hiddify'), 'приложение заменено');
ok((await text()).includes('Hiddify') && !(await text()).includes('Foxv2ray'),
   `PATCH /api/users вернул новое приложение: ${(await page.locator('#view').innerText()).split('\n').filter(l=>l.includes('Hiddify'))[0] || ''}`);

/* кольцо «Приложения клиентов» считает приложения, а не сваливает всех в «прочие» */
await go('overview');
const clNames = await page.locator('.grp:has(.clients) .clrow .fmeta b').allInnerTexts();
ok(clNames.includes('v2rayNG') && clNames.includes('Hiddify'),
   `статистика по приложениям клиентов работает: ${clNames.join(', ')}`);
ok(!clNames.some(x => x.trim() === 'прочие'),
   'ни один подписчик не попал в «прочие»: у обоих названо приложение');
const clSegs = await page.locator('.grp:has(.clients) .donut .seg').count();
ok(clSegs >= 2, `кольцо разрезано по приложениям, сегментов: ${clSegs}`);

/* ---------- хосты ---------- */
await go('hosts');
await page.click('[data-a="newhost"]');
await openDlg('#hdlg');
ok(await page.evaluate(() => document.querySelector('#hcfg [data-k="security"]').value) === 'none',
   'по умолчанию защита выключена: включается только по явному выбору');
ok((await page.locator('#hadv').innerHTML()).trim() === '', 'у tcp дополнительных настроек нет');
await page.evaluate(() => {
  const set = (k, v) => { const el = document.querySelector(`#hcfg [data-k="${k}"]`); if(el){ el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); } };
  document.querySelector('#hform [name=name]').value = 'FI Reality';
  document.querySelector('#hform [name=address]').value = 'fi.example.net';
  document.querySelector('#hnode').value = 'vps-fi';
  document.querySelector('#hnode').dispatchEvent(new Event('change'));
  set('protocol', 'vless'); set('security', 'reality'); set('network', 'tcp'); set('port', 443);
});

/* поля защиты: появились только потому, что защита выбрана */
ok(await page.locator('#hsec [data-k="dest"]').count() === 1 && await page.locator('#hsec [data-k="serverNames"]').count() === 1 &&
   await page.locator('#hsec [data-k="fp"]').count() === 0,
   'reality показал свои поля: маскированный адрес и список sni, а отпечаток — не тут');
ok(await page.locator('#hadv [data-k="fp"]').count() === 1, 'отпечаток клиента живёт в «Дополнительных настройках»');
await page.evaluate(() => { const el = document.querySelector('#hcfg [data-k="security"]'); el.value = 'tls'; el.dispatchEvent(new Event('change', {bubbles: true})); });
ok(await page.locator('#hsec [data-k="sni"]').count() === 1 && await page.locator('#hsec [data-k="rejectUnknownSni"]').count() === 1 &&
   await page.locator('#hsec [data-k="certFile"]').count() === 1 && await page.locator('#hsec [data-k="minVersion"]').count() === 0,
   'tls показал свои поля: sni, сертификаты и «отвергать чужой SNI», а версий больше нет');
ok(await page.locator('#hsec [data-k="alpn"]').count() === 0, 'alpn больше не поле панели: у Xray свои разумные договорённости');
await page.evaluate(() => { const el = document.querySelector('#hcfg [data-k="security"]'); el.value = 'none'; el.dispatchEvent(new Event('change', {bubbles: true})); });
ok((await page.locator('#hsec').innerHTML()).trim() === '', 'без защиты показывать нечего — и не показывают');
await page.evaluate(() => { const el = document.querySelector('#hcfg [data-k="security"]'); el.value = 'reality'; el.dispatchEvent(new Event('change', {bubbles: true})); });
ok((await page.textContent('#hdlg')).includes('Адрес хоста'), 'метка поля названа адресом хоста');

/* «Настройки транспорта»: свёрнуты и есть только там, где транспорту есть что настроить */
await page.evaluate(() => {
  const set = (k, v) => { const el = document.querySelector(`#hcfg [data-k="${k}"]`); el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); };
  set('security', 'tls'); set('network', 'ws');
});
ok(await page.locator('#hadv summary').count() === 1, 'у websocket есть доп. настройки, и они свёрнуты');
ok(!(await page.locator('#hadv details').first().evaluate(el => el.open)), 'блок «Настройки транспорта» по умолчанию скрыт');
await page.click('#hadv summary');
ok(await page.locator('#hadv [data-k="path"]').count() === 1 && await page.locator('#hadv [data-k="hostHeader"]').count() === 1,
   'раскрыли websocket: путь и Host-заголовок на месте');
await page.evaluate(() => { const el = document.querySelector('#hcfg [data-k="network"]'); el.value = 'grpc'; el.dispatchEvent(new Event('change', {bubbles: true})); });
ok(await page.locator('#hadv [data-k="serviceName"]').count() === 1 && await page.locator('#hadv [data-k="grpcAuthority"]').count() === 1 &&
   await page.locator('#hadv [data-k="grpcMultiMode"]').count() === 0, 'gRPC показал имя сервиса и authority, без multiMode');
await page.evaluate(() => {
  const set = (k, v) => { const el = document.querySelector(`#hcfg [data-k="${k}"]`); el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); };
  set('security', 'reality'); set('network', 'tcp');
});
ok(await page.locator('#hadv [data-k="path"]').count() === 0 && await page.locator('#hadv [data-k="fp"]').count() === 1,
   'у tcp с reality из доп. настроек остался один отпечаток');

await submit('#hform');
await wait(() => document.querySelector('#view').textContent.includes('FI Reality'));
ok((await text()).includes('FI Reality') && (await text()).includes('vps-fi'), 'хост создан и привязан к ноде');

/* правка хоста: кнопка «Изменить» открывает тот же диалог, предзаполненный текущими значениями */
await page.click('#view [data-a="hedit"]');
await openDlg('#hdlg');
ok((await page.textContent('#hdlg h3')).includes('изменение'), 'заголовок диалога говорит, что это правка');
ok(await page.evaluate(() => document.querySelector('#hform [name=name]').value) === 'FI Reality', 'имя предзаполнено');
ok(await page.evaluate(() => document.querySelector('#hcfg [data-k="security"]').value) === 'reality', 'выбранная защита предзаполнена');
ok(await page.locator('#hsec [data-k="dest"]').count() === 1, 'поля защиты показаны сразу, потому что защита уже выбрана');
ok(await page.evaluate(() => document.querySelector('#hadv [data-k="fp"]').value) === 'chrome', 'отпечаток предзаполнен значением по умолчанию');
await page.evaluate(() => {
  document.querySelector('#hform [name=name]').value = 'FI Reality-2';
  const el = document.querySelector('#hcfg [data-k="port"]'); el.value = 9412; el.dispatchEvent(new Event('change', {bubbles: true}));
});
await submit('#hform');
await wait(() => document.querySelector('#view').textContent.includes('9412'));
ok((await text()).includes('FI Reality-2') && (await text()).includes('9412'), 'хост изменён: имя и порт обновлены');

/* hy2 слушает UDP (QUIC), поэтому номер, который держит tcp-хост этой же машины, для него
   не занят: связка «443/tcp для VLESS, 443/udp для Hysteria2» рабочая — настоящий Xray
   поднимает оба инбаунда (это проверяет tools/live_demo.py). Фронт держит то же правило,
   что и бэкенд: tcp-слушателя hy2 не видит, а своего — видит */
await page.click('[data-a="newhost"]');
await openDlg('#hdlg');
await page.evaluate(() => {
  const set = (k, v) => { const el = document.querySelector(`#hcfg [data-k="${k}"]`); if(el){ el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); } };
  document.querySelector('#hform [name=name]').value = 'FI Hysteria';
  document.querySelector('#hform [name=address]').value = 'hy2.example.net';
  document.querySelector('#hnode').value = 'vps-fi';
  document.querySelector('#hnode').dispatchEvent(new Event('change'));
  set('protocol', 'hy2'); set('security', 'tls'); set('network', 'tcp');
  document.querySelector('#hcfg [data-k="port"]').value = 9412;
});
ok(await page.locator('#hsec [data-k="sni"]').count() === 1
   && await page.locator('#hsec [data-k="certFile"]').count() === 1
   && (await page.locator('#hadv').innerHTML()).trim() === ''
   && (await page.locator('#hsec').innerText()).includes('Hysteria2'),
   'hy2: из защиты только sni и свои сертификаты, блока транспорта и поля отпечатка нет, '
   + 'подсказка про QUIC/UDP на месте');
await clearToast();
await submit('#hform');
await wait(() => document.querySelector('#view').textContent.includes('FI Hysteria'));
const shared = await page.evaluate(() => (document.querySelector('#view').textContent.match(/9412/g) || []).length);
ok(shared >= 2, `hy2-хост и tcp-хост одной ноды сидят на одном порту — оба в списке: упоминаний 9412: ${shared}`);

/* два hy2 на одном номере — уже конфликт: Xray делил бы их UDP-трафик между инбаундами */
await page.click('[data-a="newhost"]');
await openDlg('#hdlg');
await page.evaluate(() => {
  const set = (k, v) => { const el = document.querySelector(`#hcfg [data-k="${k}"]`); if(el){ el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); } };
  document.querySelector('#hform [name=name]').value = 'FI Hysteria 2';
  document.querySelector('#hform [name=address]').value = 'hy2b.example.net';
  document.querySelector('#hnode').value = 'vps-fi';
  document.querySelector('#hnode').dispatchEvent(new Event('change'));
  set('protocol', 'hy2'); set('security', 'tls'); set('network', 'tcp');
  document.querySelector('#hcfg [data-k="port"]').value = 9412;
});
await clearToast();
await page.click('#hform .btn.pri');
await wait(() => document.querySelector('#toast').textContent.includes('занят'));
ok(await page.evaluate(() => document.querySelector('#hdlg').open),
   `второй hy2 на порт первого фронт не пускает: ${await toastText()}`);
await page.evaluate(() => document.querySelector('#hdlg').close());
await api(`/api/hosts/${(await (await api('/api/hosts')).json()).find(h => h.name === 'FI Hysteria').id}`, 'DELETE');
await go('hosts');

/* ---------- цепочка: её хост подсосался из цепочки ---------- */
await go('chains');
await page.click('[data-a="newchain"]');
await openDlg('#cdlg');
await page.fill('#cform [name=name]', 'FI-DE');
if(await page.locator('#hops .hopbox').count() < 2) await page.click('#addhop');
await page.evaluate(() => {
  document.querySelectorAll('#hops .hopbox').forEach((row, i) => {
    const set = (k, v) => { const el = row.querySelector(`[data-k="${k}"]`); if(el){ el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); } };
    set('node', i === 0 ? 'vps-fi' : 'home'); set('protocol', 'vless'); set('security', 'reality'); set('network', 'tcp'); set('port', 2053);
  });
});
/* адрес хоста у хопа обязателен: это тот адрес, куда подключатся и подписчик входа,
   и соседняя нода. Панель подставляет адрес ноды этого хопа, чтобы поле не было пустым. */
const NODE_ADDR = {'home': '10.8.0.1', 'vps-fi': '195.232.115.27'};
const prefilled = await page.evaluate(() => [...document.querySelectorAll('#hops .hopbox')]
  .map(r => ({node: r.querySelector('[data-k="node"]').value, address: r.querySelector('[data-k="address"]').value})));
ok(prefilled.every(h => h.address === NODE_ADDR[h.node]),
   `адрес хоста подставлен заранее — адрес ноды этого хопа: ${JSON.stringify(prefilled)}`);
await page.evaluate(() => { const el = document.querySelector('#hops .hopbox [data-k="address"]'); el.value = ''; });
await clearToast();
await page.click('#cform .btn.pri');
await page.waitForTimeout(400);
ok(await page.evaluate(() => document.querySelector('#cdlg').open),
   'адрес хоста обязателен: без него окно цепочки не сохраняет хопа');
// свой адрес хопа: туда же придёт соседняя нода и туда же пойдёт ссылка входа
await page.evaluate(() => { const el = document.querySelector('#hops .hopbox [data-k="address"]'); el.value = 'fi.example.net'; });
await submit('#cform');
await wait(() => document.querySelectorAll('#view .chain').length === 1);
ok((await text()).includes('FI-DE') && (await text()).includes('2053'), 'цепочка из двух нод создана');
ok((await text()).includes('fi.example.net'), 'на карточке цепочки виден адрес хопа, который назвал человек');
await go('hosts');
ok((await text()).includes('FI-DE'), 'хост цепочки в списке хостов — взят из цепочки, а не отдельной записью');
ok(await page.locator('#view [data-a=hdel]').count() === 1, 'хост цепочки поодиночке не удаляется (кнопки нет)');

/* ---------- правка цепочки: тот же диалог хопов, но предзаполнен и сохраняет хопа ---------- */
await go('chains');
await page.click('#view [data-a=cedit]');
await openDlg('#cdlg');
const prefill = await page.evaluate(() => ({
  title: document.querySelector('#cdlg h3').textContent,
  save: document.querySelector('#cdlg [value=ok]').textContent,
  name: document.querySelector('#cform [name=name]').value,
  hops: [...document.querySelectorAll('#hops .hopbox')].map(row => ({
    node: row.querySelector('[data-k="node"]').value,
    protocol: row.querySelector('[data-k="protocol"]').value,
    security: row.querySelector('[data-k="security"]').value,
    port: row.querySelector('[data-k="port"]').value,
    address: row.querySelector('[data-k="address"]').value,
  })),
}));
ok(prefill.title.includes('изменение') && prefill.save.includes('Сохранить') && prefill.name === 'FI-DE'
   && prefill.hops.length === 2 && prefill.hops[0].node === 'vps-fi' && prefill.hops[1].node === 'home'
   && prefill.hops[0].address === 'fi.example.net' && prefill.hops[1].address === '10.8.0.1',
   `окно правки цепочки предзаполнено её же хопами (адрес хоста у каждого): ${JSON.stringify(prefill.hops)} («${prefill.title}»)`);
const chainApi = (await (await api('/api/chains')).json())[0];
ok(chainApi.hops[0].address === 'fi.example.net' && chainApi.hops[1].address === '',
   `свой адрес хопа сохранился, а названный равным адресу ноды панель не записывает отдельно (пусто = адрес ноды): ${JSON.stringify(chainApi.hops.map(h => [h.node, h.address]))}`);

// хопа местами: те же ноды и те же порты, но вход переезжает на другую ноду.
// Свои порты своей же цепочки конфликтом быть не должны.
await page.evaluate(() => {
  const rows = [...document.querySelectorAll('#hops .hopbox')];
  for(const k of ['node', 'port']){
    const a = rows[0].querySelector(`[data-k="${k}"]`), b = rows[1].querySelector(`[data-k="${k}"]`);
    [a.value, b.value] = [b.value, a.value];
    a.dispatchEvent(new Event('change', {bubbles: true}));
    b.dispatchEvent(new Event('change', {bubbles: true}));
  }
});
await page.fill('#cform [name=name]', 'FI-DE-2');
await clearToast();
await submit('#cform');
await wait(() => [...document.querySelectorAll('#view .chain')].some(c => c.textContent.includes('FI-DE-2')));
const bodyAfterEdit = await text();
ok(!/занят/i.test(bodyAfterEdit),
   'перестановка хопов на те же порты своих же нод портом «уже занятым» не считается');

const chainsApi = await (await api('/api/chains')).json();
const hopsApi = chainsApi[0].hops;
ok(chainsApi.length === 1 && chainsApi[0].name === 'FI-DE-2'
   && hopsApi[0].node === 'home' && hopsApi[1].node === 'vps-fi',
   `правка цепочки сохранена через PATCH, хопа поменялись местами: ${hopsApi.map(h => `${h.node}:${h.port}`).join(' -> ')}`);

const nodes = await (await api('/api/nodes')).json();
const tagsOf = async (name) => {
  const id = nodes.find(n => n.name === name).id;
  const cfg = await (await api(`/api/nodes/${id}/config`)).json();
  return cfg.config.inbounds.map(i => i.tag);
};
const tagsHome = await tagsOf('home'), tagsFi = await tagsOf('vps-fi');
ok(tagsHome.includes('FI-DE-2') && !tagsFi.includes('FI-DE-2')
   && tagsFi.some(tag => tag.startsWith('FI-DE-2 hop 2')) && !tagsHome.some(tag => tag.startsWith('FI-DE-2 hop 2')),
   `вход цепочки переехал на другую ноду по-настоящему: инбаунды home ${JSON.stringify(tagsHome)}, vps-fi ${JSON.stringify(tagsFi)}`);

await go('hosts');
const hostNames = await page.evaluate(() => [...document.querySelectorAll('#view table tr')].map(r => r.textContent));
ok(hostNames.some(row => row.includes('FI-DE-2')) && !hostNames.some(row => row.includes('hop 2')),
   'список хостов: цепочка по-прежнему один хост (её вход с новым именем), промежуточные хопа не показываются');
ok(await page.locator('#view [data-a=hdel]').count() === 1,
   'и у правленой цепочки её вход поодиночке не удаляется');

/* ---------- детали хопа: у каждого хопа свои защита, транспорт и их настройки ----------
   Окно цепочки обязано различать хопа: «websocket со своим путём» на втором хопе и
   «reality со своей маской» на первом — это разные строки конфига на разных нодах. */
await go('chains');
await page.click('#view [data-a=cedit]');
await openDlg('#cdlg');
await page.evaluate(() => {
  const rows = [...document.querySelectorAll('#hops .hopbox')];
  const set = (row, k, v) => { const el = row.querySelector(`[data-k="${k}"]`); if(el){ el.value = v; el.dispatchEvent(new Event('change', {bubbles: true})); } };
  // первый хоп — reality: маска и принимаемые имена; второй — websocket + tls: путь, Host и sni
  set(rows[0], 'security', 'reality'); set(rows[0], 'network', 'tcp');
  set(rows[1], 'security', 'tls'); set(rows[1], 'network', 'ws');
});
const hopFieldsShown = await page.evaluate(() => [...document.querySelectorAll('#hops .hopbox')].map(row => ({
  node: row.querySelector('[data-k="node"]').value,
  fields: [...row.querySelectorAll('[data-k]')].map(el => el.dataset.k).filter(k =>
    ['dest', 'serverNames', 'sni', 'path', 'hostHeader', 'serviceName', 'grpcAuthority', 'fp', 'rejectUnknownSni'].includes(k)),
})));
ok(hopFieldsShown[0].fields.includes('dest') && hopFieldsShown[0].fields.includes('serverNames')
   && !hopFieldsShown[0].fields.includes('path') && !hopFieldsShown[0].fields.includes('certFile'),
   `reality-хоп показал свои поля (и не показал чужие): ${JSON.stringify(hopFieldsShown[0].fields)}`);
ok(hopFieldsShown[1].fields.includes('path') && hopFieldsShown[1].fields.includes('sni')
   && !hopFieldsShown[1].fields.includes('dest') && !hopFieldsShown[1].fields.includes('certFile'),
   `websocket-хоп показал путь и sni, но не чужие поля и не файлы сертификата: ${JSON.stringify(hopFieldsShown[1].fields)}`);

await page.evaluate(() => {
  const rows = [...document.querySelectorAll('#hops .hopbox')];
  const set = (row, k, v) => { const el = row.querySelector(`[data-k="${k}"]`); if(el){ el.value = v; el.dispatchEvent(new Event('input', {bubbles: true})); } };
  set(rows[0], 'dest', 'mirror.example.org:443');
  set(rows[0], 'serverNames', 'mirror.example.org, backup.example.org');
  set(rows[1], 'path', '/ui-hop-path'); set(rows[1], 'hostHeader', 'cdn.ui.example');
  set(rows[1], 'sni', 'ui-hop2.example.net');
  const reject = rows[1].querySelector('[data-k="rejectUnknownSni"]'); if(reject) reject.checked = true;
});
await clearToast();
await submit('#cform');
await wait(() => /цепочка изменена/i.test(document.querySelector('#toast').textContent));
const detailed = (await (await api('/api/chains')).json())[0].hops;
ok(detailed[0].dest === 'mirror.example.org:443' && detailed[0].serverNames.includes('backup.example.org'),
   `детали reality-хопа сохранены бэкендом: dest=${detailed[0].dest}, sni=${detailed[0].serverNames}`);
ok(detailed[1].path === '/ui-hop-path' && detailed[1].hostHeader === 'cdn.ui.example'
   && detailed[1].sni === 'ui-hop2.example.net' && detailed[1].rejectUnknownSni === true,
   `детали websocket-хопа сохранены бэкендом: ${detailed[1].path}, ${detailed[1].sni}`);

const cfgHome = await (await api(`/api/nodes/${nodes.find(n => n.name === 'home').id}/config`)).json();
const entryOut = cfgHome.config.outbounds.find(o => o.tag.endsWith('-> hop 2')) || {};
const hopIn = cfgHome.config.inbounds.find(i => i.tag.startsWith('FI-DE-2 hop 2'))
  || (await (await api(`/api/nodes/${nodes.find(n => n.name === 'vps-fi').id}/config`)).json()).config.inbounds
      .find(i => i.tag.startsWith('FI-DE-2 hop 2')) || {};
ok((entryOut.streamSettings?.wsSettings?.path) === '/ui-hop-path'
   && (hopIn.streamSettings?.wsSettings?.path) === '/ui-hop-path',
   'названный путь хопа оказался и на ноде-приёмнике, и в переходе отправителя: обе стороны перехода совпали');
ok((entryOut.streamSettings?.tlsSettings?.serverName) === 'ui-hop2.example.net',
   'переход называет в SNI sni хопа, а не адрес его ноды');

await page.click('#view [data-a=cedit]');
await openDlg('#cdlg');
const detailsPrefill = await page.evaluate(() => {
  const rows = [...document.querySelectorAll('#hops .hopbox')];
  const get = (row, k) => { const el = row.querySelector(`[data-k="${k}"]`); return el ? (el.type === 'checkbox' ? el.checked : el.value) : null; };
  return {dest: get(rows[0], 'dest'), serverNames: get(rows[0], 'serverNames'),
          path: get(rows[1], 'path'), hostHeader: get(rows[1], 'hostHeader'),
          sni: get(rows[1], 'sni'), reject: get(rows[1], 'rejectUnknownSni')};
});
ok(detailsPrefill.dest === 'mirror.example.org:443' && detailsPrefill.path === '/ui-hop-path'
   && detailsPrefill.sni === 'ui-hop2.example.net' && detailsPrefill.reject === true,
   `окно правки предзаполняет детали каждого хопа: ${JSON.stringify(detailsPrefill)}`);
await page.click('#cdlg [value=cancel]');
await closed('#cdlg');

/* ---------- администраторы ---------- */
await go('admins');
await page.click('[data-a="anew"]');
await openDlg('#adlg');
await fill('#adlg', {username: 'mila', password: 'viewerpass1'});
await submit('#aform');
await wait(() => document.querySelector('#view').textContent.includes('mila'));
ok((await text()).includes('mila') && (await text()).includes('Администратор'), 'новая учётка создана и она администратор: роль не выбирается');

/* ---------- настройки: сохранились в базе и переживают перезагрузку ---------- */
await go('settings');
const bottomClean = await page.evaluate(() => {
  const r = sel => { const b = document.querySelector(sel).getBoundingClientRect(); return Math.round(b.y); };
  return {flag: r('#draftFlag'), repo: r('.foottop'), acct: r('#acct'), foot: r('.foot')};
});
await page.evaluate(() => { const i = document.querySelector('#sform [name=pollInterval]'); i.value = 45; i.dispatchEvent(new Event('input', {bubbles: true})); });
await page.waitForSelector('#draftFlag:not([hidden])');
const bottomDirty = await page.evaluate(() => {
  const r = sel => { const b = document.querySelector(sel).getBoundingClientRect(); return Math.round(b.y); };
  return {repo: r('.foottop'), acct: r('#acct'), foot: r('.foot'), flag: r('#draftFlag')};
});
ok(bottomClean.repo === bottomDirty.repo && bottomClean.acct === bottomDirty.acct && bottomClean.foot === bottomDirty.foot,
   'флаг «не сохранено» ничего не сдвигает: GitHub, учётка и версия остаются на своих местах');
ok(bottomDirty.flag < bottomDirty.repo && bottomDirty.repo < bottomDirty.acct && bottomDirty.acct < bottomDirty.foot,
   'порядок низа сайдбара: «не сохранено» → GitHub/язык → учётка → версия панели');
await page.click('#ssave');
await wait(() => document.querySelector('#toast').classList.contains('show'));
const apiSettings = await page.evaluate(async () => (await fetch('/api/settings', {headers:{authorization: 'Bearer ' + localStorage.getItem('token')}})).json());
ok(apiSettings.pollInterval === 45, 'настройки легли в SQLite (pollInterval = 45)');

/* ---------- администратор: панель меняет, чужие учётки — нет ---------- */
const madeAdmin = await api('/api/admins', 'POST', {username: 'gler', password: 'glerpassword1'});
const madeAdminBody = await madeAdmin.json();
ok(madeAdmin.status === 201 && madeAdminBody.role === 'admin', `тест завёл администратора: новая учётка всегда администратор (${madeAdmin.status} ${JSON.stringify(madeAdminBody)})`);
const adminToken = (await (await api('/api/login', 'POST', {username: 'gler', password: 'glerpassword1'}, null)).json()).token;
const vctx = await b.newContext({viewport: {width: 1200, height: 800}});
await vctx.addInitScript(t => localStorage.setItem('token', t), adminToken);
const vpage = await vctx.newPage();
await vpage.goto(BASE);
await vpage.waitForSelector('#view .syscard');
ok((await vpage.textContent('#acctrole')).includes('Администратор'), 'сайдбар честно говорит: администратор');
await vpage.click('#nav a[data-p="nodes"]');
await vpage.waitForFunction(() => document.querySelector('#view').dataset.page === 'nodes');
ok(await vpage.locator('[data-a="newnode"]').count() === 1, 'администратору доступна кнопка «Добавить ноду»');
ok(await vpage.locator('#view .node').count() > 0, 'ноды администратор видит');
await vpage.click('#view .node[data-a="nedit"]');
await vpage.waitForSelector('#nedlg[open]');
ok(await vpage.evaluate(() => !document.querySelector('#nedlg button[value="ok"]').hidden
   && !document.querySelector('#nedlg [data-a="ndelete"]').hidden
   && !document.querySelector('#nedlg [data-a="ncheck"]').hidden), 'в диалоге ноды администратору доступно всё');
ok(await vpage.evaluate(() => !document.querySelector('#nedlg [data-f="address"]').readOnly), 'поля диалога редактируются');
await vpage.click('#nedlg button[value="cancel"]');
await vpage.waitForFunction(() => !document.querySelector('#nedlg').open);
await vpage.click('#nav a[data-p="users"]');
await vpage.waitForFunction(() => document.querySelector('#view').dataset.page === 'users');
ok(await vpage.locator('[data-a="new"],[data-a="del"],[data-a="toggle"]').count() > 0, 'администратор правит пользователей');
await vpage.click('#nav a[data-p="admins"]');
await vpage.waitForFunction(() => document.querySelector('#view').dataset.page === 'admins');
ok(await vpage.locator('[data-a="anew"]').count() === 0, 'новых администраторов администратор не заводит');
ok(await vpage.locator('[data-a="aedit"]').count() === 1, 'администратору доступен только его собственный аккаунт');
await vpage.click('#nav a[data-p="settings"]');
await vpage.waitForFunction(() => document.querySelector('#view').dataset.page === 'settings');
ok(await vpage.evaluate(() => !document.querySelector('#sform .savebar').hidden), 'администратор сохраняет настройки панели');
ok(await vpage.locator('#view .keys').count() === 0, 'карточки ключей на странице настроек больше нет');
await vpage.click('#nav a[data-p="admins"]');
await vpage.waitForFunction(() => document.querySelector('#view').dataset.page === 'admins');
await vpage.click('#view [data-a="aedit"]');
await vpage.waitForFunction(() => document.querySelector('#amdlg').open);
ok(await vpage.locator('#amkeys').count() === 1 && await vpage.locator('#amkeyadd').isEnabled(),
   'свои аппаратные ключи администратор ведёт в диалоге аккаунта');
ok(await vpage.evaluate(() => document.querySelector('#amstatus').disabled), 'отключить себя администратору нельзя');
await vpage.click('#amdlg button[value="cancel"]');
await vpage.waitForFunction(() => !document.querySelector('#amdlg').open);
await vpage.screenshot({path: '/tmp/shot/02-admin.png', fullPage: true});
await vctx.close();

/* ---------- владелец правит чужой аккаунт: роль, состояние, удаление ---------- */
await go('admins');
const milaRow = '#view tr:has-text("mila")';
ok(await page.locator(milaRow).count() === 1, 'в списке есть учётка mila');
ok(await page.locator(`#view tr:has-text("${OWNER.username}") [data-a="aedit"]`).count() === 1,
   'свою учётку владелец всё же видит: сменить свой пароль и свои ключи');
await page.click(`#view tr:has-text("${OWNER.username}") [data-a="aedit"]`);
await openDlg('#amdlg');
ok(await page.evaluate(() => document.querySelector('#amstatus').disabled),
   'но состояние владелец себе не меняет: он создаётся вместе с панелью');
ok(await page.evaluate(() => document.querySelector('#amdel').hidden), 'и удалить себя нельзя');
ok(await page.evaluate(() => !document.querySelector('#ampw').disabled), 'а свой пароль — можно');
await page.click('#amdlg button[value="cancel"]');
await closed('#amdlg');
await page.click(`${milaRow} [data-a="aedit"]`);
await openDlg('#amdlg');
ok((await page.textContent('#amtitle')).includes('mila'), `диалог аккаунта: ${(await page.textContent('#amtitle')).trim()}`);
ok(await page.evaluate(() => !document.querySelector('#amstatus').disabled),
   'владелец может менять состояние чужой учётки');
ok(await page.evaluate(() => document.querySelector('#ampw').disabled), 'а пароль чужой учётки — нет');
ok((await page.textContent('#ampwhint')).includes('меняет только'), 'и панель объясняет почему');
await page.selectOption('#amstatus', 'disabled');
await submit('#amdlg');
await wait(() => [...document.querySelectorAll('#view tbody tr')].some(r => r.textContent.includes('mila') && r.textContent.includes('Отключён')));
ok((await page.locator(milaRow).textContent()).includes('Отключён'), 'mila отключена: её сессии больше нет');
const milaId = await page.evaluate(() => { const rows = [...document.querySelectorAll('#view tbody tr')]; return +rows.find(r => r.textContent.includes('mila')).querySelector('[data-a="aedit"]').dataset.id; });
const milaSession = await api('/api/login', 'POST', {username: 'mila', password: 'viewerpass1'}, null);
ok(milaSession.status === 409, 'отключённый администратор не может войти');
await page.click(`${milaRow} [data-a="aedit"]`);
await openDlg('#amdlg');
await page.selectOption('#amstatus', 'active');
await submit('#amdlg');
await page.click(`${milaRow} [data-a="aedit"]`);
await openDlg('#amdlg');
ok(await page.locator('#amdel').isVisible(), 'владелец может удалить чужую учётку');
await page.click('#amdel');
await closed('#amdlg');
await wait(() => !document.querySelector('#view').textContent.includes('mila'));
ok(!(await text()).includes('mila'), 'mila удалена из списка');
await page.screenshot({path: '/tmp/shot/03-admins.png', fullPage: true});

/* ---------- карточка аппаратных ключей в настройках ---------- */
await go('settings');
await page.evaluate(() => { const c = document.querySelector('#sform [name=passkeyEnabled]'); c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); });
await page.click('#ssave');
await wait(() => document.querySelector('#toast').classList.contains('show'));
await page.waitForSelector('#sform [name=passkeyEnabled]');
ok((await page.evaluate(() => document.querySelector('#sform [name=passkeyEnabled]').checked)) === true,
   'вход по аппаратному ключу включён и сохранён');
const savedPasskey = await page.evaluate(async () => (await fetch('/api/settings', {headers:{authorization: 'Bearer ' + localStorage.getItem('token')}})).json());
ok(savedPasskey.passkeyEnabled === true, 'настройка действительно легла в базу');
await page.reload();
await go('settings');
ok(await page.inputValue('#sform [name=pollInterval]') === '45', 'после перезагрузки настройки те же — их отдаёт бэкенд');

/* ---------- удаление цепочки уносит её хост ---------- */
await go('chains');
await clearToast();
await page.click('#view [data-a=cdel]');
await wait(() => document.querySelectorAll('#view .chain').length === 0);
await go('hosts');
ok(!(await text()).includes('FI-DE'), 'хост цепочки удалён вместе с цепочкой');

/* ---------- удаление ноды уносит её хосты ---------- */
await go('nodes');
const nodesBefore = await page.locator('#view .node').count();
await openCard('vps-fi');
await page.click('#nedlg [data-a="ndelete"]');
await closed('#nedlg');
await wait(n => document.querySelectorAll('#view .node').length === n, nodesBefore - 1);
await go('hosts');
ok(!(await text()).includes('FI Reality'), 'хост ноды удалён cascade’ом вместе с нодой');

ok(errors.length === 0, `ошибок в консоли нет${errors.length ? ': ' + errors.join(' | ') : ''}`);
console.log(`\nпровалов: ${fails}`);
await b.close();
process.exit(fails ? 1 : 0);
