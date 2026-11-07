/* ---------- Настройки ----------
   USE_MOCK = true  — работает на тестовых данных, бэкенд не нужен.
   USE_MOCK = false — запросы идут на FastAPI (API_BASE), токен берётся из localStorage.
   Ожидаемые эндпоинты:
     GET    /api/users            POST /api/users
     PATCH  /api/users/{id}       DELETE /api/users/{id}
     GET    /api/nodes
     GET    /api/settings         PATCH /api/settings
     GET    /api/admins           POST /api/admins   {username,password,role}
     PATCH  /api/admins/{id}      {status} или {password}   DELETE /api/admins/{id}
     GET    /api/hosts            POST /api/hosts    {name,node,protocol,network,security,port}
     DELETE /api/hosts/{id}
     GET    /api/chains           POST /api/chains   {name, hops:[{node,protocol,network,security,port}]}
     DELETE /api/chains/{id}      (сервер сам создаёт и удаляет хост и инбаунды цепочки)
*/
const USE_MOCK = true;
const API_BASE = '';
let SUB_BASE = location.origin + '/sub/';

const GB = 1024 ** 3, DAY = 864e5;
const mock = {
  users: [
    {id:1,name:'vasya',token:'k3j9fa81xq',status:'active',used:42.5*GB},
    {id:2,name:'masha',token:'p0z7dd42lm',status:'active',used:91*GB},
    {id:3,name:'brother',token:'w8h2c5n0ty',status:'active',used:50*GB},
    {id:4,name:'old-phone',token:'a1b2c3d4e5',status:'disabled',used:12*GB},
    {id:5,name:'tv',token:'q9r8s7t6u5',status:'disabled',used:0},
  ],
  nodes: [
    {id:1,name:'home',address:'10.8.0.1',online:true,users:4,traffic:88*GB,xray:'25.8.3'},
    {id:2,name:'vps-fi',address:'10.8.0.2',online:true,users:5,traffic:107*GB,xray:'25.8.3'},
    {id:3,name:'vps-de',address:'10.8.0.3',online:true,users:3,traffic:14*GB,xray:'25.8.3'},
  ],
  hosts: [
    {id:1,name:'FI Reality',node:'vps-fi',protocol:'vless',port:443,network:'tcp',security:'reality',chain:null},
    {id:2,name:'FI TLS WS',node:'vps-fi',protocol:'vless',port:8443,network:'ws',security:'tls',chain:null},
    {id:3,name:'DE Reality',node:'vps-de',protocol:'vless',port:443,network:'tcp',security:'reality',chain:null},
    {id:4,name:'Home VMess',node:'home',protocol:'vmess',port:2083,network:'ws',security:'tls',chain:null},
    {id:5,name:'FI-DE',node:'vps-fi',protocol:'vless',port:2053,network:'tcp',security:'reality',chain:1},
    {id:6,name:'Home-FI-DE',node:'home',protocol:'vless',port:443,network:'tcp',security:'reality',chain:2},
  ],
  admins: [
    {id:1,username:'admin',role:'owner',status:'active',last:Date.now()-5*60e3,self:true},
    {id:2,username:'mila',role:'admin',status:'active',last:Date.now()-3*DAY},
    {id:3,username:'guest',role:'viewer',status:'disabled',last:0},
  ],
  settings: {panelName:'Medusa',theme:'auto',subUrl:'https://sub.example.com',subTitle:'Medusa',subInterval:12,pollInterval:30,nodeTimeout:10,sessionHours:24},
  chains: [
    {id:1,name:'FI-DE',hops:[
      {node:'vps-fi',protocol:'vless',network:'tcp',security:'reality',port:2053},
      {node:'vps-de',protocol:'vless',network:'tcp',security:'reality',port:2053}]},
    {id:2,name:'Home-FI-DE',hops:[
      {node:'home',protocol:'vless',network:'tcp',security:'reality',port:443},
      {node:'vps-fi',protocol:'vless',network:'grpc',security:'tls',port:2083},
      {node:'vps-de',protocol:'vless',network:'tcp',security:'reality',port:2083}]},
  ],
};

async function call(method, path, body){
  if(USE_MOCK) return mockCall(method, path, body);
  const r = await fetch(API_BASE + path, {
    method, headers:{'Content-Type':'application/json','Authorization':'Bearer '+(localStorage.getItem('token')||'')},
    body: body ? JSON.stringify(body) : undefined});
  if(!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.status === 204 ? null : r.json();
}
function mockCall(method, path, body){
  const m = path.match(/^\/api\/(\w+)(?:\/(\d+))?/), kind = m[1], id = +m[2];
  if(kind==='settings'){ if(method==='PATCH') Object.assign(mock.settings, body); return Promise.resolve(mock.settings); }
  if(body && body.password){ body = {...body}; delete body.password; }   // пароли в мок не кладём
  const list = mock[kind];
  if(method==='GET') return Promise.resolve(list);
  if(method==='POST'){
    const extra = kind==='users' ? {token:Math.random().toString(36).slice(2,12),status:'active',used:0}
                : kind==='hosts' ? {chain:null}
                : kind==='admins' ? {status:'active',last:0,self:false} : {};
    const o = {id:Date.now(),...extra,...body};
    list.push(o);
    if(kind==='chains'){   // как на сервере: цепочка сама создаёт хост для пользователя
      const h = o.hops[0];
      mock.hosts.push({id:o.id+1,name:o.name,node:h.node,protocol:h.protocol,port:h.port,network:h.network,security:h.security,chain:o.id});
    }
    return Promise.resolve(o);
  }
  if(kind==='chains' && method==='DELETE') mock.hosts = mock.hosts.filter(x=>x.chain!==id);
  const i = list.findIndex(x=>x.id===id);
  if(method==='PATCH') Object.assign(list[i], body);
  if(method==='DELETE') list.splice(i,1);
  return Promise.resolve(list[i]||null);
}

/* ---------- Утилиты ---------- */
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = b => b >= GB ? (b/GB).toFixed(b>=10*GB?0:1)+' ГБ' : (b/1048576).toFixed(0)+' МБ';
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>e.classList.remove('show'),1800)}
const STATUS = {active:['b-ok','Активен'],disabled:['b-off','Отключён']};
const PROTO = {vless:'VLESS',vmess:'VMess',trojan:'Trojan',ss:'Shadowsocks',hy2:'Hysteria2'};

/* ---------- Иконки ---------- */
const ICONS = {
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  users:'<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18 14.3c2 .7 3.5 2.5 3.5 5.7"/>',
  server:'<rect x="3" y="4" width="18" height="6.5" rx="2"/><rect x="3" y="13.5" width="18" height="6.5" rx="2"/><path d="M7 7.25h.01M7 16.75h.01"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
  link:'<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  shield:'<path d="M12 3l7.5 2.8v5.7c0 4.6-3.1 8-7.5 9.5-4.4-1.5-7.5-4.9-7.5-9.5V5.8L12 3z"/><path d="M9 12l2.2 2.2L15.2 10"/>',
  gear:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  trash:'<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/><path d="M10 10v6M14 10v6"/>',
  copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  power:'<path d="M12 3v9"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/>',
  key:'<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
  check:'<path d="M5 12l5 5L20 7"/>',
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  chev:'<path d="M9 6l6 6-6 6"/>',
};
const ic = n => `<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]}</svg>`;
const ROLE = {owner:'Владелец',admin:'Администратор',viewer:'Наблюдатель'};
function ago(ts){
  if(!ts) return 'Никогда';
  const m = Math.floor((Date.now()-ts)/60000);
  return m<1 ? 'Только что' : m<60 ? m+' мин назад' : m<1440 ? Math.floor(m/60)+' ч назад' : Math.floor(m/1440)+' дн. назад';
}

/* ---------- Страницы ---------- */
const pages = {
  async overview(){
    const [users,nodes,chains] = await Promise.all([call('GET','/api/users'),call('GET','/api/nodes'),call('GET','/api/chains')]);
    const act = users.filter(u=>u.status==='active').length;
    const total = nodes.reduce((a,n)=>a+n.traffic,0);
    const on = nodes.filter(n=>n.online).length;
    return `<div class="head"><h2>Обзор</h2></div>
      <div class="stats">
        <div class="stat"><i class="chip">${ic('users')}</i><b>${act} / ${users.length}</b><span>Активных пользователей</span></div>
        <div class="stat"><i class="chip">${ic('server')}</i><b>${on} / ${nodes.length}</b><span>Нод онлайн</span></div>
        <div class="stat"><i class="chip">${ic('activity')}</i><b>${fmt(total)}</b><span>Трафик за месяц</span></div>
        <div class="stat"><i class="chip">${ic('link')}</i><b>${chains.length}</b><span>Цепочек</span></div>
      </div>
      <div class="panel"><table><thead><tr><th>Нода</th><th>Адрес</th><th>Пользователей</th><th>Трафик</th></tr></thead><tbody>
      ${nodes.map(n=>`<tr><td>${esc(n.name)}</td><td class="mono">${esc(n.address)}</td><td>${n.users}</td><td>${fmt(n.traffic)}</td></tr>`).join('')}
      </tbody></table></div>`;
  },
  async users(){
    const users = await call('GET','/api/users');
    const rows = users.map(u=>{const [c,t]=STATUS[u.status]||STATUS.disabled;return `<tr>
      <td><div class="who"><span class="ava">${esc((String(u.name||'').trim()[0]||'?').toUpperCase())}</span><div>${esc(u.name)}<div class="mono">${esc(u.token)}</div></div></div></td>
      <td><span class="badge ${c}">${t}</span></td>
      <td>${fmt(u.used)}</td>
      <td><div class="acts">
        <button class="btn sm" data-a="copy" data-id="${u.id}">${ic('copy')}Подписка</button>
        <button class="btn sm" data-a="toggle" data-id="${u.id}">${ic('power')}${u.status==='disabled'?'Включить':'Отключить'}</button>
        <button class="btn sm del" data-a="del" data-id="${u.id}">${ic('trash')}Удалить</button>
      </div></td></tr>`}).join('');
    return `<div class="head"><h2>Пользователи</h2><button class="btn pri" data-a="new">${ic('plus')}Добавить</button></div>
      <div class="panel">${users.length?`<table><thead><tr><th>Имя</th><th>Статус</th><th>Трафик</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
      :'<div class="empty">Пользователей пока нет. Нажмите «Добавить», чтобы создать первого.</div>'}</div>`;
  },
  async nodes(){
    const nodes = await call('GET','/api/nodes');
    return `<div class="head"><h2>Ноды</h2></div><div class="nodes">`+nodes.map(n=>`<div class="node">
      <h3>${esc(n.name)}<span class="badge ${n.online?'b-ok live':'b-bad'}">${n.online?'Онлайн':'Недоступна'}</span></h3>
      <div class="mono">${esc(n.address)}</div>
      <dl><dt>Xray</dt><dd>${esc(n.xray)}</dd><dt>Пользователей</dt><dd>${n.users}</dd><dt>Трафик</dt><dd>${fmt(n.traffic)}</dd></dl>
    </div>`).join('')+`</div>`;
  },
  async hosts(){
    const [hosts,chains] = await Promise.all([call('GET','/api/hosts'),call('GET','/api/chains')]);
    const sec = {none:'b-off',tls:'b-ok',reality:'b-ok'};
    const cmap = Object.fromEntries(chains.map(c=>[c.id,c]));
    const direct = hosts.filter(h=>!h.chain), viaChain = hosts.filter(h=>h.chain);
    const cfg = h=>`<td><span class="badge b-proto">${esc(PROTO[h.protocol]||h.protocol)}</span></td><td>${h.port}</td><td>${esc(h.network)}</td>
      <td><span class="badge ${sec[h.security]}">${esc(h.security)}</span></td>`;
    const route = h=>{ const c = cmap[h.chain]; return c ? `<span class="route">${c.hops.map(x=>esc(x.node)).join(ic('chev'))}</span>` : esc(h.node); };
    const group = (icon,title,n,btn,inner)=>`<section class="grp"><div class="sect"><h3>${ic(icon)}${title}<span class="count">${n}</span></h3>${btn}</div>${inner}</section>`;
    const dRows = direct.map(h=>`<tr><td>${esc(h.name)}</td><td>${esc(h.node)}</td>${cfg(h)}
      <td><div class="acts"><button class="btn sm del" data-a="hdel" data-id="${h.id}">${ic('trash')}Удалить</button></div></td></tr>`).join('');
    const cRows = viaChain.map(h=>`<tr><td>${esc(h.name)}</td><td>${route(h)}</td>${cfg(h)}
      <td><div class="acts"><button class="btn sm" data-a="gochain">${ic('link')}Цепочка</button></div></td></tr>`).join('');
    const tbl = (heads,rows,empty)=>`<div class="panel">${rows?`<table><thead><tr>${heads.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">${empty}</div>`}</div>`;
    const cols = ['Протокол','Порт','Транспорт','Защита',''];
    return `<div class="head"><h2>Хосты</h2></div>`+
      group('globe','Прямые',direct.length,`<button class="btn pri" data-a="newhost">${ic('plus')}Добавить хост</button>`,
        tbl(['Название','Нода',...cols],dRows,'Прямых хостов пока нет. Нажмите «Добавить хост», чтобы создать первый.'))+
      group('link','Цепочки',viaChain.length,`<button class="btn pri" data-a="newchain">${ic('plus')}Создать цепочку</button>`,
        tbl(['Название','Маршрут',...cols],cRows,'Хостов-цепочек пока нет. Они появляются автоматически, когда вы создаёте цепочку.'));
  },
  async admins(){
    const list = await call('GET','/api/admins');
    const rows = list.map(a=>{
      const lock = a.role==='owner' || a.self, tip = lock ? 'title="Владельца и свою учётную запись менять нельзя"' : '';
      return `<tr>
        <td><div class="who"><span class="ava">${esc(a.username[0].toUpperCase())}</span><div>${esc(a.username)}${a.self?' <span class="badge b-off">вы</span>':''}</div></div></td>
        <td><span class="badge ${a.role==='owner'?'b-proto':'b-off'}">${ROLE[a.role]||esc(a.role)}</span></td>
        <td><span class="badge ${a.status==='active'?'b-ok':'b-off'}">${a.status==='active'?'Активен':'Отключён'}</span></td>
        <td>${ago(a.last)}</td>
        <td><div class="acts">
          <button class="btn sm" data-a="apw" data-id="${a.id}" data-name="${esc(a.username)}">${ic('key')}Пароль</button>
          <button class="btn sm" data-a="atoggle" data-id="${a.id}" ${lock?'disabled '+tip:''}>${ic('power')}${a.status==='active'?'Отключить':'Включить'}</button>
          <button class="btn sm del" data-a="adel" data-id="${a.id}" ${lock?'disabled '+tip:''}>${ic('trash')}Удалить</button>
        </div></td></tr>`}).join('');
    return `<div class="head"><h2>Администраторы</h2><button class="btn pri" data-a="anew">${ic('plus')}Добавить</button></div>
      <div class="panel"><table><thead><tr><th>Логин</th><th>Роль</th><th>Статус</th><th>Последний вход</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  },
  async settings(){
    const s = await call('GET','/api/settings');
    const field = (title,hint,input)=>`<div class="field"><div><div class="ft">${title}</div><div class="sub">${hint}</div></div>${input}</div>`;
    const inp = (name,val,extra='')=>`<input name="${name}" value="${esc(val)}" ${extra}>`;
    const num = (name,val,min,max)=>inp(name,val,`type="number" min="${min}" max="${max}" required`);
    const themes = {auto:'Как в системе',light:'Светлая',dark:'Тёмная'};
    const theme = `<select name="theme">${Object.entries(themes).map(([k,v])=>`<option value="${k}" ${k===s.theme?'selected':''}>${v}</option>`).join('')}</select>`;
    return `<div class="head"><h2>Настройки</h2></div>
      <form id="sform" class="sform" autocomplete="off">
        <div class="panel pad"><h3 class="sh">${ic('gear')}Общие</h3>
          ${field('Название панели','Показывается в меню и во вкладке браузера',inp('panelName',s.panelName,'required maxlength="32"'))}
          ${field('Тема','Авто повторяет тему системы',theme)}
        </div>
        <div class="panel pad"><h3 class="sh">${ic('link')}Подписки</h3>
          ${field('Адрес подписок','По нему пользователи получают ссылку вида …/sub/токен',inp('subUrl',s.subUrl,'type="url" required placeholder="https://sub.example.com"'))}
          ${field('Название профиля','Так подписка называется в приложении клиента',inp('subTitle',s.subTitle,'required maxlength="48"'))}
          ${field('Обновление в клиенте, часов','Как часто приложение само перезагружает подписку',num('subInterval',s.subInterval,1,168))}
        </div>
        <div class="panel pad"><h3 class="sh">${ic('server')}Ноды</h3>
          ${field('Опрос нод, секунд','Как часто панель собирает трафик и проверяет статус',num('pollInterval',s.pollInterval,5,3600))}
          ${field('Таймаут ответа, секунд','Через сколько нода считается недоступной',num('nodeTimeout',s.nodeTimeout,2,120))}
        </div>
        <div class="panel pad"><h3 class="sh">${ic('shield')}Безопасность</h3>
          ${field('Сессия, часов','Через сколько нужно входить заново',num('sessionHours',s.sessionHours,1,720))}
          ${field('Мой пароль','Пароль вашей учётной записи',`<button type="button" class="btn" data-a="mypw">${ic('key')}Сменить пароль</button>`)}
        </div>
        <div class="savebar"><button class="btn pri" id="ssave" disabled>${ic('check')}Сохранить</button></div>
      </form>`;
  },
  async chains(){
    const [chains,nodes] = await Promise.all([call('GET','/api/chains'),call('GET','/api/nodes')]);
    const on = Object.fromEntries(nodes.map(n=>[n.name,n.online]));
    const word = n=>{const m=n%10,c=n%100;return n+' '+(m===1&&c!==11?'хоп':m>=2&&m<=4&&(c<12||c>14)?'хопа':'хопов')};
    const cfg = h=>[PROTO[h.protocol]||h.protocol, h.network!=='tcp'?h.network:'', h.security!=='none'?h.security:''].filter(Boolean).join(' ')+' :'+h.port;
    const items = chains.map(c=>{
      const problem = c.hops.some(h=>!(h.node in on)) ? 'Нода удалена' : c.hops.some(h=>!on[h.node]) ? 'Нода недоступна' : null;
      const path = c.hops.map((h,k)=>(k?'<div class="link'+(problem?' dead':'')+'"></div>':'')+
        `<div><div class="pill ${on[h.node]?'':'off'}"><b>${esc(h.node)}</b><div class="mono">${esc(cfg(h))}</div></div>
         <div class="sub" style="text-align:center">${k===0?'Вход':k===c.hops.length-1?'Выход':'Транзит'}</div></div>`).join('');
      return `<div class="chain"><div class="meta"><b>${esc(c.name)}</b><div class="sub">${word(c.hops.length)}</div></div>
        <div class="path">${path}</div>
        <span class="badge ${problem?'b-bad':'b-ok'}">${problem||'Работает'}</span>
        <button class="btn sm del" data-a="cdel" data-id="${c.id}">${ic('trash')}Удалить</button></div>`}).join('');
    return `<div class="head"><h2>Цепочки</h2><button class="btn pri" data-a="newchain">${ic('plus')}Создать цепочку</button></div>`+
      (chains.length?`<div class="chains">${items}</div>`
      :'<div class="panel"><div class="empty">Цепочек пока нет. Нажмите «Создать цепочку», выберите ноды и настройте протокол на каждой.</div></div>');
  },
};

let page = 'overview', first = true;
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

function moveInd(){
  const a = document.querySelector('aside a.on'), i = $('#ind');
  if(!a || getComputedStyle(i).display==='none') return;
  i.style.width = a.offsetWidth+'px'; i.style.height = a.offsetHeight+'px';
  i.style.transform = `translate(${a.offsetLeft}px,${a.offsetTop}px)`;
  requestAnimationFrame(()=>i.classList.add('ready'));
}
addEventListener('resize', moveInd);

function countUp(el){
  const parts = el.textContent.split(/(\d+)/), t0 = performance.now();
  (function f(t){
    const k = Math.min(1,(t-t0)/800), e = 1-Math.pow(1-k,3);
    el.textContent = parts.map(s=>/^\d+$/.test(s)?Math.round(+s*e):s).join('');
    if(k<1) requestAnimationFrame(f);
  })(t0);
}

async function show(p){
  const animate = !reduced && (first || (p && p !== page));
  first = false;
  page = p || page;
  document.querySelectorAll('aside a').forEach(a=>a.classList.toggle('on',a.dataset.p===page));
  moveInd();
  const v = $('#view');
  try{ v.innerHTML = await pages[page](); }
  catch(e){ v.innerHTML = `<div class="empty">Не удалось загрузить данные: ${esc(e.message)}.<br>Проверьте, что бэкенд запущен и токен задан.</div>`; }
  v.classList.toggle('enter', animate);
  if(animate){
    v.querySelectorAll('.stat,.node,.chain,tbody tr,.pad,.sect').forEach((el,i)=>el.style.setProperty('--i',Math.min(i,12)));
    v.querySelectorAll('.stat b').forEach(countUp);
  }
}

/* ---------- События ---------- */
document.querySelector('aside').addEventListener('click', e=>{ const a = e.target.closest('a[data-p]'); if(a) show(a.dataset.p); });
$('#view').addEventListener('click', async e=>{
  const b = e.target.closest('[data-a]'); if(!b) return;
  const a = b.dataset.a, id = +b.dataset.id;
  try{
    if(a==='new'){ $('#dlg').returnValue=''; return $('#dlg').showModal(); }
    if(a==='newchain') return openChain();
    if(a==='newhost') return openHost();
    if(a==='gochain') return show('chains');
    if(a==='anew') return openAdmin();
    if(a==='apw') return openPw(id, b.dataset.name);
    if(a==='mypw'){ const me = (await call('GET','/api/admins')).find(x=>x.self); return openPw(me.id, me.username); }
    if(a==='atoggle'){
      const x = (await call('GET','/api/admins')).find(y=>y.id===id);
      await call('PATCH','/api/admins/'+id,{status:x.status==='active'?'disabled':'active'}); return show();
    }
    if(a==='adel'){ if(!confirm('Удалить администратора? Он больше не сможет войти в панель.')) return; await call('DELETE','/api/admins/'+id); toast('Удалён'); return show(); }
    if(a==='hdel'){ if(!confirm('Удалить хост?')) return; await call('DELETE','/api/hosts/'+id); toast('Удалён'); return show(); }
    if(a==='cdel'){ if(!confirm('Удалить цепочку? Её хост и инбаунды на нодах тоже удалятся.')) return; await call('DELETE','/api/chains/'+id); toast('Удалена'); return show(); }
    if(a==='copy'){
      const u = (await call('GET','/api/users')).find(x=>x.id===id);
      await navigator.clipboard.writeText(SUB_BASE + u.token); return toast('Ссылка подписки скопирована');
    }
    if(a==='toggle'){
      const u = (await call('GET','/api/users')).find(x=>x.id===id);
      await call('PATCH','/api/users/'+id,{status:u.status==='disabled'?'active':'disabled'});
    }
    if(a==='del'){ if(!confirm('Удалить пользователя? Это действие нельзя отменить.')) return; await call('DELETE','/api/users/'+id); toast('Удалён'); }
    show();
  }catch(err){ toast('Ошибка: '+err.message) }
});
$('#dlg').addEventListener('close', async ()=>{
  if($('#dlg').returnValue!=='ok') return;
  const f = new FormData($('#uform'));
  try{
    await call('POST','/api/users',{name:f.get('name')});
    toast('Пользователь создан'); $('#uform').reset(); show('users');
  }catch(err){ toast('Ошибка: '+err.message) }
});

/* ----- общие настройки инбаунда: протокол / транспорт / защита / порт ----- */
const PROTOS = ['vless','vmess','trojan','ss'];
const SEC_BY = {vless:['none','tls','reality'],vmess:['none','tls'],trojan:['tls','reality'],ss:['none']};
const opts = (list,label)=>list.map(v=>`<option value="${v}">${esc(label?label[v]:v)}</option>`).join('');
const cfgHTML = ()=>`<div class="cfgwrap"><div class="cfgh"><span>Протокол</span><span>Транспорт</span><span>Защита</span><span>Порт</span></div>
  <div class="cfg"><select data-k="protocol" aria-label="Протокол">${opts(PROTOS,PROTO)}</select>
  <select data-k="network" aria-label="Транспорт">${opts(['tcp','ws','grpc'])}</select>
  <select data-k="security" aria-label="Защита">${opts(['none','tls','reality'])}</select>
  <input data-k="port" type="number" min="1" max="65535" required placeholder="Порт" aria-label="Порт"></div></div>`;
const K = (root,k)=>root.querySelector(`[data-k="${k}"]`);
function syncCfg(root){
  const sec = K(root,'security'), net = K(root,'network'), proto = K(root,'protocol').value, ok = SEC_BY[proto];
  [...sec.options].forEach(o=>o.disabled = !ok.includes(o.value));
  if(!ok.includes(sec.value)) sec.value = ok[0];
  [...net.options].forEach(o=>o.disabled = (sec.value==='reality' && o.value==='ws') || (proto==='ss' && o.value!=='tcp'));
  if(net.selectedOptions[0].disabled) net.value = [...net.options].find(o=>!o.disabled).value;
}
function initCfg(root){
  K(root,'security').value = 'reality'; syncCfg(root);
  root.querySelector('.cfgwrap').addEventListener('change', e=>{
    if(e.target.matches('[data-k="protocol"],[data-k="security"]')) syncCfg(root);
  });
}
const readCfg = root => ({protocol:K(root,'protocol').value, network:K(root,'network').value, security:K(root,'security').value, port:+K(root,'port').value});

/* ----- занятые порты на ноде (хосты + инбаунды цепочек) ----- */
let ctx = {hosts:[],chains:[],nodes:[]};
async function loadCtx(){
  const [hosts,chains,nodes] = await Promise.all([call('GET','/api/hosts'),call('GET','/api/chains'),call('GET','/api/nodes')]);
  ctx = {hosts,chains,nodes};
}
const taken = node => new Set([
  ...ctx.hosts.filter(h=>h.node===node).map(h=>h.port),
  ...ctx.chains.flatMap(c=>c.hops.filter(h=>h.node===node).map(h=>h.port)),
]);
function freePort(node, extra=[]){
  const used = new Set([...taken(node), ...extra]);
  const p = [443,8443,2053,2083,2087,2096].find(x=>!used.has(x));
  if(p) return p;
  let r = 10000 + Math.floor(Math.random()*50000); while(used.has(r)) r++;
  return r;
}
const nodeOptions = ()=>ctx.nodes.map(n=>`<option>${esc(n.name)}</option>`).join('');

/* ----- диалог «Новый хост» ----- */
async function openHost(){
  await loadCtx();
  if(!ctx.nodes.length) return toast('Сначала добавьте ноду');
  $('#hform').reset();
  $('#hnode').innerHTML = nodeOptions();
  $('#hcfg').innerHTML = cfgHTML(); initCfg($('#hcfg'));
  K($('#hcfg'),'port').value = freePort($('#hnode').value);
  $('#hdlg').returnValue = ''; $('#hdlg').showModal();
}
$('#hnode').onchange = ()=>{ K($('#hcfg'),'port').value = freePort($('#hnode').value); };
$('#hform').addEventListener('submit', e=>{
  if(e.submitter && e.submitter.value!=='ok') return;
  const port = readCfg($('#hcfg')).port, node = $('#hnode').value;
  if(taken(node).has(port)){ e.preventDefault(); toast(`Порт ${port} на ноде ${node} уже занят`); }
});
$('#hdlg').addEventListener('close', async ()=>{
  if($('#hdlg').returnValue!=='ok') return;
  try{
    await call('POST','/api/hosts',{name:$('#hform [name=name]').value, node:$('#hnode').value, ...readCfg($('#hcfg'))});
    toast('Хост создан'); show();
  }catch(err){ toast('Ошибка: '+err.message) }
});

/* ----- диалог «Новая цепочка» ----- */
const hopRows = ()=>[...document.querySelectorAll('#hops .hopbox')];
const rowNode = r => K(r,'node').value;
const rowPort = r => +K(r,'port').value;
function setHopPort(row){
  const same = hopRows().filter(r=>r!==row && rowNode(r)===rowNode(row)).map(rowPort);
  K(row,'port').value = freePort(rowNode(row), same);
}
function renumber(){
  const rows = hopRows();
  rows.forEach((r,i)=>{
    r.querySelector('.hop span').textContent = i===0?'Вход':i===rows.length-1?'Выход':'Транзит';
    r.querySelector('.hop button').disabled = rows.length<=2;
  });
}
function addHop(){
  const box = $('#hops');
  if(box.children.length>=6) return toast('Максимум 6 хопов');
  const prev = box.lastElementChild ? rowNode(box.lastElementChild) : null;
  const row = document.createElement('div'); row.className = 'hopbox';
  row.innerHTML = `<div class="hop"><span></span><select data-k="node" aria-label="Нода">${nodeOptions()}</select><button type="button" class="btn sm">Убрать</button></div>${cfgHTML()}`;
  const other = ctx.nodes.find(n=>n.name!==prev); if(other) K(row,'node').value = other.name;
  initCfg(row); setHopPort(row);
  K(row,'node').onchange = ()=>setHopPort(row);
  row.querySelector('.hop button').onclick = ()=>{ row.remove(); renumber(); };
  box.append(row); renumber();
}
async function openChain(){
  await loadCtx();
  if(ctx.nodes.length<2) return toast('Для цепочки нужны минимум две ноды');
  $('#cform').reset(); $('#hops').innerHTML = ''; addHop(); addHop();
  $('#cdlg').returnValue = ''; $('#cdlg').showModal();
}
$('#addhop').onclick = addHop;
$('#cform').addEventListener('submit', e=>{
  if(e.submitter && e.submitter.value!=='ok') return;
  const rows = hopRows(); let err = null;
  rows.forEach((r,i)=>{
    const n = rowNode(r), port = rowPort(r);
    if(i && n===rowNode(rows[i-1])) err ||= 'Соседние хопы должны быть на разных нодах';
    if(taken(n).has(port)) err ||= `Порт ${port} на ноде ${n} уже занят`;
    if(rows.slice(0,i).some(o=>rowNode(o)===n && rowPort(o)===port)) err ||= `Порт ${port} на ноде ${n} повторяется в цепочке`;
  });
  if(err){ e.preventDefault(); toast(err); }
});
$('#cdlg').addEventListener('close', async ()=>{
  if($('#cdlg').returnValue!=='ok') return;
  const hops = hopRows().map(r=>({node:rowNode(r), ...readCfg(r)}));
  try{ await call('POST','/api/chains',{name:$('#cform [name=name]').value, hops}); toast('Цепочка создана'); show(); }
  catch(err){ toast('Ошибка: '+err.message) }
});

/* ----- администраторы ----- */
function openAdmin(){ $('#aform').reset(); $('#adlg').returnValue = ''; $('#adlg').showModal(); }
$('#adlg').addEventListener('close', async ()=>{
  if($('#adlg').returnValue!=='ok') return;
  const f = new FormData($('#aform'));
  try{ await call('POST','/api/admins',{username:f.get('username'),password:f.get('password'),role:f.get('role')}); toast('Администратор создан'); show(); }
  catch(err){ toast('Ошибка: '+err.message) }
});
let pwTarget = null;
function openPw(id, name){
  pwTarget = id; $('#pwtitle').textContent = 'Новый пароль для ' + name;
  $('#pwform').reset(); $('#pwdlg').returnValue = ''; $('#pwdlg').showModal();
}
$('#pwform').addEventListener('submit', e=>{
  if(e.submitter && e.submitter.value!=='ok') return;
  const f = new FormData($('#pwform'));
  if(f.get('p1')!==f.get('p2')){ e.preventDefault(); toast('Пароли не совпадают'); }
});
$('#pwdlg').addEventListener('close', async ()=>{
  if($('#pwdlg').returnValue!=='ok') return;
  try{ await call('PATCH','/api/admins/'+pwTarget,{password:new FormData($('#pwform')).get('p1')}); toast('Пароль изменён'); }
  catch(err){ toast('Ошибка: '+err.message) }
});

/* ----- настройки панели ----- */

function applyTheme(theme) {
    const root = document.documentElement;

    if (theme === 'light' || theme === 'dark') {
        root.dataset.theme = theme;
    } else {
        delete root.dataset.theme;
    }
}

function applySettings(s) {
    if (!s) return;

    const panelName = s.panelName || 'Medusa';

    $('#pname').textContent = panelName;
    document.title = panelName;

    applyTheme(s.theme || 'auto');

    if (s.subUrl) {
        SUB_BASE = s.subUrl.replace(/\/+$/, '') + '/sub/';
    }
}

// Мгновенное переключение темы
$('#view').addEventListener('change', e => {
    if (e.target.matches('#sform select[name="theme"]')) {
        applyTheme(e.target.value);
    }

    if (e.target.closest('#sform')) {
        const save = $('#ssave');
        if (save) save.disabled = false;
    }
});

// Отслеживание изменений настроек
$('#view').addEventListener('input', e => {
    if (e.target.closest('#sform')) {
        const save = $('#ssave');
        if (save) save.disabled = false;
    }
});

// Сохранение настроек
$('#view').addEventListener('submit', async e => {
    if (e.target.id !== 'sform') return;

    e.preventDefault();

    const f = new FormData(e.target);

    const body = {
        panelName: f.get('panelName').trim(),
        theme: f.get('theme'),
        subUrl: f.get('subUrl').trim().replace(/\/+$/, ''),
        subTitle: f.get('subTitle').trim(),
        subInterval: +f.get('subInterval'),
        pollInterval: +f.get('pollInterval'),
        nodeTimeout: +f.get('nodeTimeout'),
        sessionHours: +f.get('sessionHours')
    };

    try {
        applySettings(await call('PATCH', '/api/settings', body));
        $('#ssave').disabled = true;
        toast('Настройки сохранены');
    } catch (err) {
        toast('Ошибка: ' + err.message);
    }
});

function applySettings(s){
  $('#pname').textContent = s.panelName; document.title = s.panelName;
  if(s.theme==='auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = s.theme;
  SUB_BASE = s.subUrl.replace(/\/+$/,'') + '/sub/';
}
['input','change'].forEach(ev=>$('#view').addEventListener(ev, e=>{ if(e.target.closest('#sform')) $('#ssave').disabled = false; }));
$('#view').addEventListener('submit', async e=>{
  if(e.target.id!=='sform') return;
  e.preventDefault();
  const f = new FormData(e.target);
  const body = {panelName:f.get('panelName').trim(), theme:f.get('theme'), subUrl:f.get('subUrl').trim().replace(/\/+$/,''), subTitle:f.get('subTitle').trim(),
    subInterval:+f.get('subInterval'), pollInterval:+f.get('pollInterval'), nodeTimeout:+f.get('nodeTimeout'), sessionHours:+f.get('sessionHours')};
  try{ applySettings(await call('PATCH','/api/settings',body)); $('#ssave').disabled = true; toast('Настройки сохранены'); }
  catch(err){ toast('Ошибка: '+err.message) }
});
document.querySelectorAll('aside a[data-i]').forEach(a=>a.insertAdjacentHTML('afterbegin', ic(a.dataset.i)));

$('#mode').textContent = USE_MOCK ? 'Тестовые данные' : 'Подключено к API';
(async()=>{ try{ applySettings(await call('GET','/api/settings')); }catch(e){} show(); })();
