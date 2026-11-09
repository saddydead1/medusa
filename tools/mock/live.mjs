import {chromium} from 'playwright';
const BASE = process.env.MEDUSA_UI_URL || 'http://localhost:8000/';
const MOCK = BASE + '?mock=1';


const b = await chromium.launch();
const ctx = await b.newContext({viewport: {width: 1380, height: 900}});
const page = await ctx.newPage();
let fails = 0;
const ok = (c, m) => { console.log((c ? 'PASS  ' : 'FAIL  ') + m); if(!c) fails++; };

await page.goto(MOCK);
await page.evaluate(() => { localStorage.clear(); });
await page.reload();
await page.waitForTimeout(500);
ok((await page.textContent('#mode')).includes('0.1.0'), 'версия из pyproject.toml: ' + await page.textContent('#mode'));
ok(await page.getAttribute('html', 'data-theme') === null, 'стартовая тема — авто (как в системе)');

await page.click('a[data-p="settings"]');
await page.waitForTimeout(300);
await page.selectOption('select[name="theme"]', 'dark');
await page.waitForTimeout(400);
ok(await page.getAttribute('html', 'data-theme') === 'dark', 'тема применена сразу');
let store = await page.evaluate(() => JSON.parse(localStorage.getItem('medusa:settings') || '{}'));
ok(store.theme === 'dark', 'настройка сохранена: ' + JSON.stringify(store.theme));
ok(await page.isVisible('#draftFlag') === false, 'нет хвоста «несохранённых изменений»');

await page.click('a[data-p="overview"]');
await page.waitForTimeout(300);
ok(await page.getAttribute('html', 'data-theme') === 'dark', 'тема живёт на другой странице');

await page.click('a[data-p="users"]');
await page.waitForTimeout(300);
await page.reload();
await page.waitForTimeout(600);
ok(await page.getAttribute('html', 'data-theme') === 'dark', 'тема пережила перезагрузку (F5)');

await page.click('a[data-p="settings"]');
await page.waitForTimeout(300);
ok(await page.inputValue('select[name="theme"]') === 'dark', 'в форме настроек выбрана «Тёмная»');
ok(await page.getAttribute('html', 'data-theme') === 'dark', 'и сама тема на месте');

// несохранённый черновик по другим полям переживает переход и перезагрузку
await page.fill('input[name="subTitle"]', 'Моя подписка');
await page.waitForTimeout(300);
ok(await page.isVisible('#draftFlag'), 'показан флаг «не сохранено»');
ok(await page.isEnabled('#ssave'), 'кнопка «Сохранить» активна');
await page.click('a[data-p="chains"]');
await page.waitForTimeout(300);
ok(await page.isVisible('#draftFlag'), 'флаг виден и на других страницах');
await page.reload();
await page.waitForTimeout(600);
await page.click('a[data-p="settings"]');
await page.waitForTimeout(300);
ok(await page.inputValue('input[name="subTitle"]') === 'Моя подписка', 'черновик пережила перезагрузку');

await page.click('#ssave');
await page.waitForTimeout(500);
store = await page.evaluate(() => JSON.parse(localStorage.getItem('medusa:settings') || '{}'));
ok(store.subTitle === 'Моя подписка', 'сохранение применило все поля');
ok(await page.isVisible('#draftFlag') === false, 'флаг пропал после сохранения');
ok(await page.getAttribute('html', 'data-theme') === 'dark', 'тема всё ещё тёмная');

// отмена
await page.fill('input[name="panelName"]', 'Гидра');
await page.waitForTimeout(250);
ok(await page.textContent('#pname') === 'Гидра', 'название предпросмотрено сразу');
await page.click('[data-a="sdiscard"]');
await page.waitForTimeout(400);
ok(await page.inputValue('input[name="panelName"]') === store.panelName, '«Отменить» вернул сохранённое значение');
ok(await page.textContent('#pname') === store.panelName, 'и предпросмотр тоже отменён');

// смена на светлую — тоже сохраняется
await page.selectOption('select[name="theme"]', 'light');
await page.waitForTimeout(400);
await page.reload();
await page.waitForTimeout(600);
ok(await page.getAttribute('html', 'data-theme') === 'light', 'светлая тема тоже сохраняется');
await page.click('a[data-p="settings"]');
await page.waitForTimeout(300);
ok(await page.inputValue('select[name="theme"]') === 'light', 'форма показывает «Светлая»');

/* ---------- учётка и её аппаратные ключи: снять свой ключ можно самому ----------
   Ключ здесь намеренно подложен в тестовую базу руками: браузер в тесте никакого
   WebAuthn не делает, а проверить нужно именно кнопку снятия в диалоге аккаунта. */
await page.evaluate(() => { mock.keys = [{id:4242, nickname:'YubiKey 5', algo:'ES256',
  aaguid:'00000000-0000-0000-0000-000000000000', signCount:7, createdAt:Date.now()-3600e3}]; });
await page.click('a[data-p="admins"]'); await page.waitForTimeout(400);
await page.click('#view tr:first-child [data-a="aedit"]');
await page.waitForFunction(() => document.querySelector('#amdlg').open);
ok((await page.textContent('#amkeys')).includes('YubiKey 5'), 'в диалоге аккаунта виден его ключ');
ok(await page.locator('#amkeys [data-a="amkeydel"]').count() === 1, 'у своего ключа есть кнопка «Снять ключ»');
await page.screenshot({path: '/tmp/shot/mock-amdlg.png'});
await page.click('#amkeys [data-a="amkeydel"]');
await page.waitForTimeout(500);
ok((await page.textContent('#amkeys')).includes('Ключей нет'), 'ключ снят самим собой: ' + (await page.textContent('#amkeys')).trim());
ok((await page.textContent('#toast')).includes('снят'), 'и панель это подтвердила: ' + (await page.textContent('#toast')).trim());
await page.click('#amdlg button[value="cancel"]');
await page.waitForFunction(() => !document.querySelector('#amdlg').open);

/* карточки ключей на странице настроек больше нет: ключи ведутся в диалоге аккаунта */
await page.click('a[data-p="settings"]'); await page.waitForTimeout(400);
ok(await page.locator('#view .keys').count() === 0, 'настроек «мои аппаратные ключи» больше нет');
ok(await page.locator('#sform [name=passkeyEnabled]').count() === 1, 'а разрешение входа ключом осталось настройкой');

/* учётка в сайдбаре: ник и роль — ровными строками, без «съехавшего» текста */
const acctBox = await page.evaluate(() => {
  const r = s => { const b = document.querySelector(s).getBoundingClientRect(); return {x:b.x, y:b.y, bottom:b.bottom, right:b.right}; };
  return {name: r('#acctname'), role: r('#acctrole'), card: r('#acct'), aside: r('aside')};
});
ok(Math.abs(acctBox.name.x - acctBox.role.x) < 1, `ник и роль на одной вертикали (${Math.round(acctBox.name.x)} и ${Math.round(acctBox.role.x)})`);
ok(acctBox.name.bottom <= acctBox.role.y + 1, 'роль идёт строкой под ником');
ok(acctBox.card.right <= acctBox.aside.right, 'карточка учётки не вылезает за сайдбар');

await b.close();
console.log(fails ? `\n${fails} провалов` : '\nвсе проверки пройдены');
process.exit(fails ? 1 : 0);
