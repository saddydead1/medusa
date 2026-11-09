import {chromium} from 'playwright';
const BASE = process.env.MEDUSA_UI_URL || 'http://localhost:8000/';
const MOCK = BASE + '?mock=1';
const b=await chromium.launch();
const ctx=await b.newContext({viewport:{width:1360,height:1100}});
let fails=0; const ok=(c,m)=>{console.log((c?'PASS  ':'FAIL  ')+m); if(!c)fails++;};
const pagesList=['overview','users','hosts','chains','nodes','admins','settings'];
for(const lng of ['ru','en']){
  const p=await ctx.newPage();
  const warns=[];
  p.on('console', m=>{ if(m.text().startsWith('[i18n]')) warns.push(m.text()); });
  await p.goto(MOCK);
  await p.evaluate(l=>{ localStorage.clear(); localStorage.setItem('medusa:lang', l); }, lng);
  await p.reload(); await p.waitForTimeout(800);
  for(const pg of pagesList){
    await p.click(`a[data-p="${pg}"]`); await p.waitForTimeout(420);
    // в rendered-тексте не должно быть сырых ключей словаря
    const text = await p.evaluate(()=>{
      const bits=[document.querySelector('#view').innerText, document.querySelector('aside nav').innerText];
      document.querySelectorAll('#view [title],#view [placeholder],#view [aria-label]').forEach(e=>bits.push(e.title||'',e.placeholder||'',e.getAttribute('aria-label')||''));
      return bits.join('\n');
    });
    const keys = await p.evaluate(()=>Object.keys(I18N.ru));
    const leak = keys.filter(k=>text.split(/[^A-Za-z0-9_.]/).includes(k));
    ok(leak.length===0, `${lng}/${pg}: сырых ключей словаря в тексте нет` + (leak.length?': '+leak.join(', '):''));
  }
  ok(warns.length===0, `${lng}: t() не предупредил об отсутствующих строках`+(warns.length?': '+[...new Set(warns)].join(' | '):''));

  // словари должны совпадать по составу: иначе на одном языке страница молча
  // отрисуется чужими строками или ключом вместо слова
  const parity = await p.evaluate(()=>{
    const ru = Object.keys(I18N.ru), en = Object.keys(I18N.en);
    const onlyRu = ru.filter(k=>!en.includes(k));
    const onlyEn = en.filter(k=>!ru.includes(k));
    return {ru: ru.length, en: en.length, onlyRu, onlyEn};
  });
  ok(parity.ru===parity.en && !parity.onlyRu.length && !parity.onlyEn.length,
     `${lng}: словари ru/en совпадают по ключам (${parity.ru})` +
     (parity.onlyRu.length?': только в ru '+parity.onlyRu.join(', '):'') +
     (parity.onlyEn.length?': только в en '+parity.onlyEn.join(', '):''));
  await p.close();
}
await b.close();
console.log(fails?`\n${fails} провалов`:'\nвсе проверки пройдены'); process.exit(fails?1:0);
