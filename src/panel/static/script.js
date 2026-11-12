/* ---------- Режим работы панели ----------
   По умолчанию данные берутся у бэкенда (FastAPI + SQLite, src/panel).
   Тестовый режим включается приставкой ?mock=1 в адресе — тогда работает мок
   прямо во фронтенде, бэкенд для данных не нужен (в моке учётка владельца на месте,
   чтобы мок-проверки видели панель целиком).

   Эндпоинты бэкенда. Кроме /api/login, /api/fido/* и /api/meta всё требует сессии
   (`Authorization: Bearer <token>`, токен лежит в localStorage['token']); без неё панель
   показывает окно входа. Права: администратор — правка панели,
   но не чужих учёток, владелец — всё и защита своей учётки.
     GET    /api/meta               версия панели из pyproject.toml
     GET    /api/system             метрики сервера: ЦП, память, диски, uptime
     POST   /api/login              {username,password} -> {token,admin}
     POST   /api/fido/begin         {username?} -> {options}: вызов входа аппаратным ключом
     POST   /api/fido/login         {response} -> {token,admin}
     GET    /api/me                 кто мы: {id,username,role,expiresAt,sessions}
     POST   /api/logout             выбрасывает сессии этой учётки
     GET    /api/users              POST /api/users {name,client?}
     PATCH  /api/users/{id}         {status|client|name}      DELETE /api/users/{id}
     GET    /api/nodes              POST /api/nodes {name,address,apiKey,apiPort?}
     PATCH  /api/nodes/{id}         {name|address|apiPort|apiKey|online|xray}   DELETE
     GET    /api/nodes/{id}/key     API-ключ ноды целиком: только тем, кто может писать
     POST   /api/nodes/{id}/check   проверка связи (панель ходит к ноде и сама, по таймеру)
     GET    /api/hosts              POST /api/hosts {name,node,protocol,network,security,port}
     DELETE /api/hosts/{id}         (хост цепочки удаляется вместе с цепочкой)
     GET    /api/chains             POST /api/chains {name, hops:[{node,protocol,network,security,port}]}
     PATCH  /api/chains/{id}        {name,...}  DELETE /api/chains/{id}
     GET    /api/settings           PATCH /api/settings
     GET    /api/admins             POST /api/admins {username,password}   (новая учётка всегда администратор)
     PATCH  /api/admins/{id}        {status|password}    DELETE /api/admins/{id}
     GET    /api/admins/{id}/keys   аппаратные ключи учётки
     POST   /api/admins/{id}/keys/begin   {nickname?} -> {options}: вызов записи ключа
     POST   /api/admins/{id}/keys         {response,nickname?}    DELETE .../keys/{keyId}
   Логику самого VPN (Xray на нодах) пока не делали: трафик и статусы нод будут
   приходить позже, когда займёмся нодовым агентом вплотную. */
let USE_MOCK = new URLSearchParams(location.search).has('mock');const API_BASE = '';
let SUB_BASE = location.origin + '/sub/';

/* Копирование, которое живёт и на https, и на голом http из локальной сети:
   clipboard API браудеры разрешают только в безопасном контексте, поэтому на http
   (а панель из LAN — всегда http) fallback через временный textarea + execCommand.
   Safari на чужом http иначе вообще ничего не копирует. */
async function copyText(v){
  if(navigator.clipboard && window.isSecureContext){
    try{ await navigator.clipboard.writeText(v); return true; }catch(e){}
  }
  const ta = document.createElement('textarea');
  ta.value = v; ta.style.position='fixed'; ta.style.left='-9999px';
  document.body.appendChild(ta); ta.focus(); ta.setSelectionRange(0, ta.value.length);
  let ok = false;
  try{ ok = document.execCommand('copy'); }catch(e){}
  document.body.removeChild(ta);
  return ok;
}
let PANEL_VERSION = 'dev';

/* ---------- Хранилище настроек панели ----------
   KEY_SAVED — сохранённые настройки (в тестовом режиме это «база», в API-режиме — кэш сервера).
   KEY_DRAFT — несохранённые правки формы: выбранная тема и остальные значения не теряются
   ни при переходе на другую страницу, ни при перезагрузке.
   localStorage переживает и перезагрузку, и закрытие вкладки. */
const SETTINGS_DEFAULTS = {panelName:'Medusa',theme:'auto',subUrl:location.origin + '/sub',subTitle:'Medusa',subInterval:12,pollInterval:30,nodeTimeout:10,sessionHours:24,passkeyEnabled:false};
const KEY_SAVED = 'medusa:settings', KEY_DRAFT = 'medusa:settings:draft';
const lsGet = k => { try { return JSON.parse(localStorage.getItem(k) || 'null'); } catch { return null; } };
const lsSet = (k,v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };
const lsDel = k => { try { localStorage.removeItem(k); } catch {} };

/* ---------- Язык интерфейса ----------
   Язык хранится в localStorage, поэтому переключенный язык живёт до тех пор,
   пока его не сбросили. Меняется кнопкой RU/EN в подвале сайдбара. */
const KEY_LANG = 'medusa:lang';
let lang = lsGet(KEY_LANG) === 'en' ? 'en' : 'ru';
const LOCALE = {ru:'ru-RU', en:'en-GB'};
const UNITS = () => lang === 'ru' ? {gb:'ГБ', mb:'МБ'} : {gb:'GB', mb:'MB'};

const I18N = {
  ru: {
    'nav.overview':'Обзор','nav.users':'Пользователи','nav.hosts':'Хосты','nav.chains':'Цепочки',
    'nav.nodes':'Ноды','nav.admins':'Администраторы','nav.settings':'Настройки',
    'btn.newNode':'Добавить ноду','dlg.node.title':'Новая нода','dlg.node.name':'Название','dlg.node.address':'Адрес (IP или домен)',
    'dlg.node.apiPort':'Порт API ноды','dlg.node.key':'API-ключ ноды',
    'dlg.node.keyHint':'API-ключ нода печатает в консоль при первом запуске.',
    'node.openTip':'Изменить ноду','node.version':'Версия ноды','node.notReported':'неизвестно',
    'dlg.nodeEdit.apiKey':'API-ключ','dlg.nodeEdit.check':'Связь с панелью',
    'dlg.nodeEdit.fp':'отпечаток API-ключа: {fp}','dlg.nodeEdit.keyMissing':'API-ключа пока нет: впишите тот, что напечатала нода',
    'toast.nodeSaved':'нода обновлена','toast.stale':'этой ноды уже нет: список обновлён',
    'btn.checkNode':'Проверить связь',
    'node.neverChecked':'ещё не проверялась',
    'node.checkOk':'Нода отвечает, API-ключ подходит: {fp}','node.checkBad':'Связь не сложилась: {msg}',
    'node.config':'Конфиг Xray','node.configLoading':'собираем конфиг…',
    'confirm.delNode':'Удалить ноду? Её хосты удалятся вместе с ней.',
    'toast.nodeCreated':'Нода добавлена',
    'footer.repo.title':'Репозиторий панели','footer.unsaved':'не сохранено',
    'footer.unsaved.title':'Настройки изменены, но ещё не сохранены','footer.version':'Версия панели — {v}',
    'lang.switch':'Переключить язык интерфейса',
    'btn.cancel':'Отмена','btn.save':'Сохранить','btn.create':'Создать','btn.add':'Добавить',
    'btn.delete':'Удалить','btn.enable':'Включить','btn.disable':'Отключить','btn.subscription':'Подписка',
    'btn.newHost':'Добавить хост',
    'btn.newChain':'Создать цепочку','btn.chain':'Цепочка','btn.discard':'Отменить','btn.addhop':'Добавить хоп',
    'dlg.user.title':'Новый пользователь','dlg.user.name':'Имя (email в Xray)',
    'dlg.admin.title':'Новый администратор','dlg.admin.login':'Логин',
    'dlg.admin.password':'Пароль (минимум 8 символов)',
    'dlg.admin.hint':'Администратор управляет пользователями, хостами, цепочками и нодами. Настройки и других администраторов меняет владелец.',
    'dlg.host.title':'Новый хост','dlg.host.name':'Название (его увидит пользователь)','dlg.host.node':'Нода','dlg.host.address':'Адрес хоста (IP или домен)',
    'dlg.chain.title':'Новая цепочка','dlg.chain.name':'Название хоста (его увидит пользователь)',
    'dlg.chain.hint':'Пользователь увидит цепочку как один хост и подключится к первой ноде. Инбаунд каждой ноды и переход между нодами создаются автоматически.',
    'cfg.protocol':'Протокол','cfg.transport':'Транспорт','cfg.security':'Защита','cfg.port':'Порт',
    'cfg.sec.reality.dest':'Маскированный адрес (dest)','cfg.sec.fp':'Отпечаток клиента (utls)',
    'cfg.sec.reality.serverNames':'Какие SNI принимать (через запятую)',
    'cfg.sec.reality.hint':'Ключи панель сгенерирует сама. Клиент называет SNI из принимаемых имён — по умолчанию это домен маскировки (dest), поэтому адресом хоста может быть и IP. Для Clash и Mihomo reality поверх Xray 26.9.8+ не работает: Mihomo не добавляет нужный Xray ключ рукопожатия — таким подписчикам заводите хосты tls или ws.',
    'cfg.sec.tls.sni':'SNI','cfg.sec.tls.cert':'Файл сертификата (путь на ноде)','cfg.sec.tls.key':'Файл закрытого ключа (путь на ноде)',
    'cfg.sec.tls.rejectSni':'Отвергать чужой SNI',
    'cfg.sec.tls.hint':'Оставьте сертификаты пустыми — нода сама выпустит self-signed на sni. Есть настоящий сертификат (например, от certbot) — впишите пути к обоим файлам. Строгому клиенту нужно назвать отпечаток сертификата pinnedPeerCertSha256.',
    'cfg.protocol.short':'Протокол','cfg.port.short':'Порт',
    'th.address':'Адрес','th.node':'Нода','th.users':'Пользователей','th.traffic':'Трафик',
    'th.name':'Имя','th.title':'Название','th.status':'Статус','th.login':'Логин','th.role':'Роль',
    'th.lastLogin':'Последний вход','th.route':'Маршрут',
    'status.active':'Активен','status.disabled':'Отключён',
    'role.owner':'Владелец','role.admin':'Администратор','role.self':'вы',
    'overview.title':'Обзор','stat.activeUsers':'Активных пользователей','stat.nodesOnline':'Нод онлайн',
    'stat.traffic':'Трафик за месяц','stat.chains':'Цепочек',
    'overview.nodesTraffic':'Трафик по нодам','overview.share':'{p}% от общего',
    'overview.trafficStale':'не обновляется','node.traffic':'Трафик ноды',
    'node.trafficSilent':'счётчики молчат: {why}',
    'overview.clients':'Приложения клиентов','overview.clientsAria':'Распределение подписок по приложениям клиентов',
    'subs.one':'подписка','subs.few':'подписки','subs.many':'подписок',
    'clients.activeTitle':'активных подписок','client.unknown':'прочие',
    'empty.nodes':'Нод пока нет. Панель ещё ни к одной ноде не подключилась.',
    'sys.server':'Сервер','sys.cpu':'ЦП','sys.ram':'ОЗУ','sys.disk':'Диск','sys.diskMount':'Диск {mount}',
    'sys.updated':'обновлено в {time}','sys.mocked':'тестовые данные, обновлено в {time}',
    'sys.unavailable':'Метрики сервера недоступны: бэкенд не отвечает на /api/system.',
    'node.online':'Онлайн','node.offline':'Недоступна','node.xray':'Xray',
    'hosts.direct':'Прямые','hosts.viaChains':'Цепочки',
    'empty.users':'Пользователей пока нет. Нажмите «Добавить», чтобы создать первого.',
    'empty.direct':'Прямых хостов пока нет. Нажмите «Добавить хост», чтобы создать первый.',
    'empty.viaChain':'Хостов-цепочек пока нет. Они появляются автоматически, когда вы создаёте цепочку.',
    'empty.chains':'Цепочек пока нет. Нажмите «Создать цепочку», выберите ноды и настройте протокол на каждой.',
    'chain.entry':'Вход','chain.transit':'Транзит','chain.exit':'Выход','chain.ok':'Работает',
    'chain.nodeRemoved':'Нода удалена','chain.nodeDown':'Нода недоступна',
    'hops.one':'хоп','hops.few':'хопа','hops.many':'хопов',
    'settings.title':'Настройки','settings.general':'Общие','settings.subs':'Подписки','settings.nodes':'Ноды','settings.security':'Безопасность',
    'settings.panelName':'Название панели','settings.panelName.hint':'Показывается в меню и во вкладке браузера',
    'settings.theme':'Тема','settings.theme.hint':'Авто повторяет тему системы',
    'theme.auto':'Как в системе','theme.light':'Светлая','theme.dark':'Тёмная',
    'settings.subUrl':'Адрес подписок','settings.subUrl.hint':'Целиком, до /sub включительно: панель дописывает к нему только токен пользователя',
    'settings.subTitle':'Название профиля','settings.subTitle.hint':'Так подписка называется в приложении клиента',
    'settings.subInterval':'Обновление в клиенте, часов','settings.subInterval.hint':'Как часто приложение само перезагружает подписку',
    'settings.pollInterval':'Опрос нод, секунд','settings.pollInterval.hint':'Как часто панель сама ходит к нодам и перечитывает открытую страницу',
    'settings.nodeTimeout':'Таймаут ответа, секунд','settings.nodeTimeout.hint':'Через сколько нода считается недоступной',
    'settings.sessionHours':'Сессия, часов','settings.sessionHours.hint':'Через сколько нужно входить заново',
    'settings.unsaved':'Есть несохранённые изменения',
    'ago.never':'Никогда','ago.now':'Только что','ago.min':'{n} мин назад','ago.hour':'{n} ч назад','ago.day':'{n} дн. назад',
    'toast.saved':'Настройки сохранены','toast.discarded':'Изменения отменены','toast.passwordChanged':'Пароль изменён',
    'toast.adminCreated':'Администратор создан','toast.chainCreated':'Цепочка создана','toast.userCreated':'Пользователь создан',
    'toast.deleted':'Удалён','toast.chainDeleted':'Удалена','toast.chainEdited':'Цепочка изменена','toast.subCopied':'Ссылка подписки скопирована',
    'toast.error':'Ошибка: {msg}','toast.loadSettings':'Не удалось получить настройки: {msg}',
    'auth.login':'Вход в панель','auth.user':'Логин','auth.password':'Пароль','auth.btn':'Войти','auth.key':'Войти ключом',
    'auth.bad':'Вход не прошёл: {msg}','auth.logout':'Выйти','auth.logoutTip':'Выйти из панели: сессия перестанет работать',
    'auth.required':'Необходимо войти','auth.in':'Вы вошли под учёткой {name}','btn.edit':'Изменить','settings.sessionUntil':'ваша сессия истекает {time}',
    'auth.insecure':'Браузер не даёт работать с аппаратными ключами: нужен HTTPS (или localhost)',
    'settings.passkey':'Вход по аппаратному ключу','settings.passkey.hint':'Разрешить входить ключом (FIDO2/WebAuthn) вместо пароля',
    'keys.none':'Ключей нет',
    'keys.add':'Записать ключ','keys.del':'Снять ключ','keys.signed':'подписей: {n}','keys.added':'Ключ записан','keys.removed':'Ключ снят',
    'keys.bad':'Ключ не записался: {msg}','keys.nick':'Как назвать ключ','keys.unnamed':'ключ без названия',
    'dlg.adminEdit':'Аккаунт {name}','dlg.adminEdit.login':'Логин','dlg.adminEdit.password':'Новый пароль (минимум 8 символов)',
    'dlg.adminEdit.passwordOwnOnly':'Пароль этого аккаунта меняет только {name}: чужой пароль панель не меняет','dlg.adminEdit.passwordHint':'Пароль меняет только владелец аккаунта — при смене пароля все сессии этого аккаунта перестают работать.',
    'dlg.adminEdit.status':'Состояние','dlg.adminEdit.keys':'Ключи','dlg.adminEdit.delete':'Удалить аккаунт',
    'dlg.adminEdit.save':'Сохранить','dlg.adminEdit.disabled':'Отключён','dlg.adminEdit.active':'Активен',
    'toast.adminSaved':'Аккаунт обновлён','toast.adminDisabled':'Аккаунт отключён','toast.adminEnabled':'Аккаунт включён',
    'toast.loggedOut':'Вы вышли из панели',
    'toast.themeLocal':'Тема сохранена в браузере, сервер ответил ошибкой: {msg}',
    'toast.noNodes':'Сначала добавьте ноду',
    'toast.portTaken':'Порт {port} на ноде {node} уже занят','toast.portDup':'Порт {port} на ноде {node} повторяется в цепочке',
    'chain.hopAddress':'Адрес хопа','chain.hopAddressPh':'адрес ноды','chain.hopAddressHint':
      'Куда придёт соседняя нода: домен или IP этого хопа. Пусто — адрес ноды. У входа цепочки тот же адрес попадает в ссылку подписки.',
    'confirm.delAdmin':'Удалить администратора? Он больше не сможет войти в панель.',
    'confirm.delHost':'Удалить хост?','confirm.delChain':'Удалить цепочку? Её хост и инбаунды на нодах тоже удалятся.',
    'confirm.delUser':'Удалить пользователя? Это действие нельзя отменить.',
    'err.load':'Не удалось загрузить данные: {msg}.<br>Проверьте, что бэкенд запущен и токен задан.',
    'toast.hostCreated':'Хост создан','toast.hostEdited':'Хост обновлён',
    'dlg.host.editTitle':'Хост: изменение',
    'cfg.adv':'Настройки транспорта','cfg.adv.path':'Путь (path)','cfg.adv.hostHeader':'Host-заголовок','cfg.adv.serviceName':'Имя сервиса (gRPC)',
    'cfg.adv.grpc.authority':'Authority (к кому «обращается» gRPC)',
    'chain.maxHops':'Максимум {n} хопов','btn.remove':'Убрать',
    'dlg.chain.editTitle':'Цепочка: изменение',
    'chain.minNodes':'Для цепочки нужны минимум две ноды',
    'chain.hopSameNode':'Соседние хопы должны быть на разных нодах',

  },
  en: {
    'nav.overview':'Overview','nav.users':'Users','nav.hosts':'Hosts','nav.chains':'Chains',
    'nav.nodes':'Nodes','nav.admins':'Administrators','nav.settings':'Settings',
    'btn.newNode':'Add node','dlg.node.title':'New node','dlg.node.name':'Name','dlg.node.address':'Address (IP or domain)',
    'dlg.node.apiPort':'Node API port','dlg.node.key':'Node API key',
    'dlg.node.keyHint':'The node prints its API key to the console on first start.',
    'node.openTip':'Edit this node','node.version':'Node version','node.notReported':'unknown',
    'dlg.nodeEdit.apiKey':'API key','dlg.nodeEdit.check':'Panel link',
    'dlg.nodeEdit.fp':'API key fingerprint: {fp}','dlg.nodeEdit.keyMissing':'no API key yet: type the one the node printed',
    'toast.nodeSaved':'node updated','toast.stale':'this node is gone: the list was refreshed',
    'btn.checkNode':'Check link',
    'node.neverChecked':'not checked yet',
    'node.checkOk':'The node answers and the API key matches: {fp}','node.checkBad':'No working link: {msg}',
    'node.config':'Xray config','node.configLoading':'building the config…',
    'confirm.delNode':'Delete this node? Its hosts go with it.',
    'toast.nodeCreated':'Node added',
    'footer.repo.title':'Panel repository','footer.unsaved':'unsaved',
    'footer.unsaved.title':'Settings changed but not saved yet','footer.version':'Panel version — {v}',
    'lang.switch':'Switch interface language',
    'btn.cancel':'Cancel','btn.save':'Save','btn.create':'Create','btn.add':'Add',
    'btn.delete':'Delete','btn.enable':'Enable','btn.disable':'Disable','btn.subscription':'Subscription',
    'btn.newHost':'Add host',
    'btn.newChain':'Create chain','btn.chain':'Chain','btn.discard':'Discard','btn.addhop':'Add hop',
    'dlg.user.title':'New user','dlg.user.name':'Name (email in Xray)',
    'dlg.admin.title':'New administrator','dlg.admin.login':'Username',
    'dlg.admin.password':'Password (at least 8 characters)',
    'dlg.admin.hint':'An administrator manages users, hosts, chains and nodes. Only the owner can change settings and other administrators.',
    'dlg.host.title':'New host','dlg.host.name':'Name (the user will see it)','dlg.host.node':'Node','dlg.host.address':'Host address (IP or domain)',
    'dlg.chain.title':'New chain','dlg.chain.name':'Host name (the user will see it)',
    'dlg.chain.hint':'The user sees a chain as a single host and connects to the first node. Every node gets its inbound and the hop to the next node automatically.',
    'cfg.protocol':'Protocol','cfg.transport':'Transport','cfg.security':'Security','cfg.port':'Port',
    'cfg.sec.reality.dest':'Camouflage address (dest)','cfg.sec.fp':'Client fingerprint (utls)',
    'cfg.sec.reality.serverNames':'Accepted SNIs (comma-separated)',
    'cfg.sec.reality.hint':'The panel generates the keypair itself. Clients name an SNI from the accepted names — by default the camouflage domain (dest) — so the host address may be an IP. Clash and Mihomo cannot do reality over Xray 26.9.8+ (Mihomo omits the key share Xray requires) — give those subscribers tls or ws hosts.',
    'cfg.sec.tls.sni':'SNI','cfg.sec.tls.cert':'Certificate file (path on the node)','cfg.sec.tls.key':'Private key file (path on the node)',
    'cfg.sec.tls.rejectSni':'Reject unknown SNI',
    'cfg.sec.tls.hint':'Leave the certificate fields empty and the node issues a self-signed cert for the sni. Have a real certificate (e.g. from certbot) — give both file paths. Strict clients must pin it via pinnedPeerCertSha256.',
    'cfg.protocol.short':'Protocol','cfg.port.short':'Port',
    'th.address':'Address','th.node':'Node','th.users':'Users','th.traffic':'Traffic',
    'th.name':'Name','th.title':'Name','th.status':'Status','th.login':'Username','th.role':'Role',
    'th.lastLogin':'Last sign-in','th.route':'Route',
    'status.active':'Active','status.disabled':'Disabled',
    'role.owner':'Owner','role.admin':'Administrator','role.self':'you',
    'overview.title':'Overview','stat.activeUsers':'Active users','stat.nodesOnline':'Nodes online',
    'stat.traffic':'Traffic this month','stat.chains':'Chains',
    'overview.nodesTraffic':'Traffic per node','overview.share':'{p}% of total',
    'overview.trafficStale':'not updating','node.traffic':'Node traffic',
    'node.trafficSilent':'counters are silent: {why}',
    'overview.clients':'Client apps','overview.clientsAria':'Subscription split by client app',
    'subs.one':'subscription','subs.few':'subscriptions','subs.many':'subscriptions',
    'clients.activeTitle':'active subscriptions','client.unknown':'other',
    'empty.nodes':'No nodes yet. The panel has not connected to any node.',
    'sys.server':'Server','sys.cpu':'CPU','sys.ram':'RAM','sys.disk':'Disk','sys.diskMount':'Disk {mount}',
    'sys.updated':'updated at {time}','sys.mocked':'demo data, updated at {time}',
    'sys.unavailable':'Server metrics are unavailable: the backend does not answer /api/system.',
    'node.online':'Online','node.offline':'Offline','node.xray':'Xray',
    'hosts.direct':'Direct','hosts.viaChains':'Chains',
    'empty.users':'No users yet. Press “Add” to create the first one.',
    'empty.direct':'No direct hosts yet. Press “Add host” to create the first one.',
    'empty.viaChain':'No chain hosts yet. They appear automatically when you create a chain.',
    'empty.chains':'No chains yet. Press “Create chain”, pick the nodes and configure the protocol on each.',
    'chain.entry':'Entry','chain.transit':'Transit','chain.exit':'Exit','chain.ok':'Working',
    'chain.nodeRemoved':'Node removed','chain.nodeDown':'Node offline',
    'hops.one':'hop','hops.few':'hops','hops.many':'hops',
    'settings.title':'Settings','settings.general':'General','settings.subs':'Subscriptions','settings.nodes':'Nodes','settings.security':'Security',
    'settings.panelName':'Panel name','settings.panelName.hint':'Shown in the menu and in the browser tab',
    'settings.theme':'Theme','settings.theme.hint':'Auto follows the system theme',
    'theme.auto':'Follow system','theme.light':'Light','theme.dark':'Dark',
    'settings.subUrl':'Subscription base URL','settings.subUrl.hint':'Full URL up to /sub: the panel appends only the user token to it',
    'settings.subTitle':'Profile name','settings.subTitle.hint':'This is how the subscription is named in the client app',
    'settings.subInterval':'Client refresh, hours','settings.subInterval.hint':'How often the client app reloads the subscription',
    'settings.pollInterval':'Node polling, seconds','settings.pollInterval.hint':'How often the panel visits nodes on its own and re-reads the page you have open',
    'settings.nodeTimeout':'Response timeout, seconds','settings.nodeTimeout.hint':'After how long a node counts as unavailable',
    'settings.sessionHours':'Session, hours','settings.sessionHours.hint':'After how long you have to sign in again',
    'settings.unsaved':'There are unsaved changes',
    'ago.never':'Never','ago.now':'Just now','ago.min':'{n} min ago','ago.hour':'{n} h ago','ago.day':'{n} d ago',
    'toast.saved':'Settings saved','toast.discarded':'Changes discarded','toast.passwordChanged':'Password changed',
    'toast.adminCreated':'Administrator created','toast.chainCreated':'Chain created','toast.userCreated':'User created',
    'toast.deleted':'Deleted','toast.chainDeleted':'Deleted','toast.chainEdited':'Chain updated','toast.subCopied':'Subscription link copied',
    'toast.error':'Error: {msg}','toast.loadSettings':'Could not load settings: {msg}',
    'auth.login':'Sign in to the panel','auth.user':'Login','auth.password':'Password','auth.btn':'Sign in','auth.key':'Sign in with a key',
    'auth.bad':'Sign-in failed: {msg}','auth.logout':'Sign out','auth.logoutTip':'Sign out: this session stops working',
    'auth.required':'Sign-in required','auth.in':'Signed in as {name}','btn.edit':'Edit','settings.sessionUntil':'your session ends at {time}',
    'auth.insecure':'The browser will not use hardware keys here: HTTPS (or localhost) is required',
    'settings.passkey':'Hardware key sign-in','settings.passkey.hint':'Allow signing in with a FIDO2/WebAuthn key instead of a password',
    'keys.none':'No keys',
    'keys.add':'Register key','keys.del':'Remove key','keys.signed':'signatures: {n}','keys.added':'Key registered','keys.removed':'Key removed',
    'keys.bad':'Key was not registered: {msg}','keys.nick':'Name this key','keys.unnamed':'key without a name',
    'dlg.adminEdit':'Account {name}','dlg.adminEdit.login':'Login','dlg.adminEdit.password':'New password (at least 8 characters)',
    'dlg.adminEdit.passwordOwnOnly':'Only {name} can change this account password: the panel never changes another account password','dlg.adminEdit.passwordHint':'Only the account owner can change its password; changing it stops every session of that account.',
    'dlg.adminEdit.status':'Status','dlg.adminEdit.keys':'Keys','dlg.adminEdit.delete':'Delete account',
    'dlg.adminEdit.save':'Save','dlg.adminEdit.disabled':'Disabled','dlg.adminEdit.active':'Active',
    'toast.adminSaved':'Account updated','toast.adminDisabled':'Account disabled','toast.adminEnabled':'Account enabled',
    'toast.loggedOut':'Signed out',
    'toast.themeLocal':'Theme saved in the browser, the server answered with an error: {msg}',
    'toast.noNodes':'Add a node first',
    'toast.portTaken':'Port {port} on node {node} is already taken','toast.portDup':'Port {port} on node {node} repeats inside the chain',
    'chain.hopAddress':'Hop address','chain.hopAddressPh':'node address','chain.hopAddressHint':
      'Where the previous node connects: this hop\'s domain or IP. Empty means the node address. For the chain entry the same address goes into the subscription link.',
    'confirm.delAdmin':'Delete this administrator? They will no longer be able to sign in.',
    'confirm.delHost':'Delete this host?','confirm.delChain':'Delete this chain? Its host and the inbounds on the nodes will be removed too.',
    'confirm.delUser':'Delete this user? This cannot be undone.',
    'err.load':'Could not load data: {msg}.<br>Check that the backend is running and the token is set.',
    'toast.hostCreated':'Host created','toast.hostEdited':'Host updated',
    'dlg.host.editTitle':'Host: edit',
    'cfg.adv':'Transport settings','cfg.adv.path':'Path','cfg.adv.hostHeader':'Host header','cfg.adv.serviceName':'Service name (gRPC)',
    'cfg.adv.grpc.authority':'Authority (gRPC target host)',
    'chain.maxHops':'At most {n} hops','btn.remove':'Remove',
    'dlg.chain.editTitle':'Chain: edit',
    'chain.minNodes':'A chain needs at least two nodes',
    'chain.hopSameNode':'Neighbouring hops must be on different nodes',

  },
};

function t(key, vars){
  let s = (I18N[lang] && I18N[lang][key]) ?? I18N.ru[key] ?? key;
  if(s === key) console.warn('[i18n] нет строки:', key);   // чтобы такие дыры было видно сразу
  if(vars) for(const [k,v] of Object.entries(vars)) s = s.replaceAll('{'+k+'}', v);
  return s;
}
/* русские формы «1 хоп / 2 хопа / 5 хопов»; в английском просто one/other */
const ruForm = n => { const m = n % 10, c = n % 100; return (m === 1 && c !== 11) ? 0 : (m >= 2 && m <= 4 && (c < 12 || c > 14)) ? 1 : 2; };
const plural = (n, one, few, many) => lang === 'ru' ? [one, few, many][ruForm(n)] : (n === 1 ? one : many);
const timeStr = d => d.toLocaleTimeString(LOCALE[lang], {hour:'2-digit', minute:'2-digit'});


/* ---------- Сессия, учётка и роль ----------
   Панель без учётки не работает: бэкенд требует сессию на всех /api (кроме /api/login,
   /api/fido/* и /api/meta). Токен живёт в localStorage, поэтому вход переживает перезагрузку.
   Роли в панели две: владелец и администратор. Пишет всякий вошедший; разница только
   в разборе чужих аккаунтов — это умеет лишь владелец. */
const KEY_TOKEN = 'token', KEY_ME = 'medusa:me';
let me = null;
const canWrite = () => !!me;
const canManage = () => !!me && me.role === 'owner';
const store = (k, v) => { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, JSON.stringify(v)); } catch {} };
const tokenGet = () => { try { return localStorage.getItem(KEY_TOKEN) || ''; } catch { return ''; } };
const tokenSet = v => { try { v ? localStorage.setItem(KEY_TOKEN, v) : localStorage.removeItem(KEY_TOKEN); } catch {} };

function meSet(next){
  me = next;
  store(KEY_ME, me);
  renderAccount();
}

function renderAccount(){
  const box = $('#acct'); if(!box) return;
  box.hidden = !me;
  if(!me) return;
  $('#acctname').textContent = me.username;
  const role = $('#acctrole');
  role.textContent = roleLabel(me.role);
  $('#acctava').textContent = (String(me.username||'?')[0]||'?').toUpperCase();
}

function askLogin(message){
  const dlg = $('#logdlg');
  const err = $('#logerr');
  if(message){ err.textContent = message; err.hidden = false; } else { err.hidden = true; }
  if(!dlg.open){
    $('#lform').reset();
    dlg.addEventListener('cancel', e => e.preventDefault());   // закрыть нельзя: либо вход, либо ничего
    dlg.showModal();
    $('#lform').username.focus();
  }
}

async function afterLogin(){
  try{ me = await call('GET','/api/me'); store(KEY_ME, me); }catch{ return askLogin(t('auth.bad',{msg:'/api/me'})); }
  renderAccount();
  toast(t('auth.in',{name:me.username}));
  try{ savedSettings = {...savedSettings, ...(await call('GET','/api/settings'))}; lsSet(KEY_SAVED, savedSettings); }catch(e){}
  applySettings(settingsNow()); syncSettingsUI();
  await show(); startRefresh();
}

async function passwordLogin(){
  const f = $('#lform');
  try{
    const r = await call('POST','/api/login',{username:f.username.value, password:f.password.value});
    tokenSet(r.token); meSet(r.admin);
    $('#logdlg').close();
    await afterLogin();
  }catch(err){ askLogin(t('auth.bad',{msg:err.message})); }
}

async function keyLogin(){
  if(!webauthnReady()) return askLogin(t('auth.insecure'));
  const name = $('#lform').username.value.trim();
  try{
    const options = await call('POST','/api/fido/begin', name ? {username:name} : {});
    const response = await fidoGet(options.options);
    const r = await call('POST','/api/fido/login',{response});
    tokenSet(r.token); meSet(r.admin);
    $('#logdlg').close();
    await afterLogin();
  }catch(err){ askLogin(t('auth.bad',{msg:err.message})); }
}

async function logout(){
  try{ await call('POST','/api/logout'); }catch{}
  tokenSet(''); meSet(null); stopRefresh();
  toast(t('toast.loggedOut'));
  askLogin();
}

/* ---------- WebAuthn: вызов браузера и перевод байтов в base64url ----------
   Панель отдаёт вызовы base64url-строками, браузер хочет Uint8Array — и обратно.
   navigator.credentials работает только на HTTPS или localhost: на http по IP ключ не проверить. */
const b64u = buf => { const b = new Uint8Array(buf); let s = ''; for(const c of b) s += String.fromCharCode(c); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };
const unb64u = str => { const bin = atob(String(str).replace(/-/g,'+').replace(/_/g,'/') + '==='.slice(0,(4-String(str).length%4)%4)); const u = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i] = bin.charCodeAt(i); return u; };
const webauthnReady = () => !!(window.isSecureContext && navigator.credentials && window.PublicKeyCredential);

async function fidoCreate(options){
  const pub = {...options, rpId:options.rp.id, challenge:unb64u(options.challenge),
               user:{...options.user, id:unb64u(options.user.id)}, attestation:'none'};
  if(options.excludeCredentials) pub.excludeCredentials = options.excludeCredentials.map(c=>({id:unb64u(c.id), type:'public-key'}));
  const cred = await navigator.credentials.create({publicKey:pub});
  return { id: b64u(cred.rawId), response:{ clientDataJSON:b64u(cred.response.clientDataJSON),
           attestationObject:b64u(cred.response.attestationObject) } };
}

async function fidoGet(options){
  const pub = {...options, challenge:unb64u(options.challenge), userVerification:'preferred'};
  if(options.allowCredentials) pub.allowCredentials = options.allowCredentials.map(c=>({id:unb64u(c.id), type:'public-key'}));
  const answer = await navigator.credentials.get({publicKey:pub});
  return { id: b64u(answer.rawId), response:{ clientDataJSON:b64u(answer.response.clientDataJSON),
           authenticatorData:b64u(answer.response.authenticatorData), signature:b64u(answer.response.signature) } };
}

function keysHTML(keys, editable){
  if(!keys.length) return `<div class="sub mono">${t('keys.none')}</div>`;
  return keys.map(k=>`<div class="keyrow"><div><b>${esc(k.nickname || t('keys.unnamed'))}</b>`+
    `<div class="sub mono">${esc(k.algo)} · ${t('keys.signed',{n:k.signCount})} · ${esc(ago(k.createdAt))}</div></div>`+
    /* data-a именно amkeydel: обработщик снятия ключа живёт на диалоге аккаунта */
    (editable?`<button type="button" class="btn sm del" data-a="amkeydel" data-id="${k.id}">${ic('trash')}${t('keys.del')}</button>`:'')+`</div>`).join('');
}

async function addKey(adminId, nickname){
  if(!webauthnReady()) return toast(t('auth.insecure'));
  const begin = await call('POST', `/api/admins/${adminId}/keys/begin`, {});
  const response = await fidoCreate(begin.options);
  await call('POST', `/api/admins/${adminId}/keys`, {response, nickname:nickname||null});
  toast(t('keys.added'));
}

const GB = 1024 ** 3, DAY = 864e5;
const mock = {
  users: [
    {id:1,name:'vasya',token:'k3j9fa81xq',status:'active',used:42.5*GB,client:'happ'},
    {id:2,name:'masha',token:'p0z7dd42lm',status:'active',used:91*GB,client:'clash-verge'},
    {id:3,name:'brother',token:'w8h2c5n0ty',status:'active',used:50*GB,client:'clash-meta'},
    {id:4,name:'old-phone',token:'a1b2c3d4e5',status:'disabled',used:12*GB,client:'clash-verge'},
    {id:5,name:'tv',token:'q9r8s7t6u5',status:'disabled',used:0,client:'v2rayng'},
  ],
  nodes: [
    {id:1,name:'home',address:'10.8.0.1',online:true,users:4,traffic:88*GB,xray:'25.8.3',apiPort:9443,apiPath:'/node/health',keySet:true,keyMasked:'sk-api…3f9c2-81b7a',fingerprint:'3f9c2-81b7a',agent:'0.1.0',seenAt:Date.now()-4*60*1000,configRev:4,configDirty:false,appliedRev:4,appliedAt:Date.now()-4*60*1000,applyError:null},
    {id:2,name:'vps-fi',address:'10.8.0.2',online:true,users:5,traffic:107*GB,xray:'25.8.3',apiPort:9443,apiPath:'/node/health',keySet:true,keyMasked:'sk-api…c40b9-1de75',fingerprint:'c40b9-1de75',agent:'0.1.0',seenAt:Date.now()-90*1000,configRev:2,configDirty:true,appliedRev:1,appliedAt:Date.now()-30*60e3,applyError:null},
    {id:3,name:'vps-de',address:'10.8.0.3',online:false,users:3,traffic:14*GB,trafficError:'на ноде нет бинарника xray — счётчики снять нечем',xray:null,apiPort:9443,apiPath:'/node/health',keySet:true,keyMasked:'sk-api…7d301-90cb2',fingerprint:'7d301-90cb2',agent:null,seenAt:0,configRev:1,configDirty:false,appliedRev:0,appliedAt:null,applyError:'нода не ответила: ConnectError'},
  ],
  hosts: [
    {id:1,name:'FI Reality',node:'vps-fi',address:'fi.example.com',protocol:'vless',port:443,network:'tcp',security:'reality',chain:null},
    {id:2,name:'FI TLS WS',node:'vps-fi',address:'fi.example.com',protocol:'vless',port:8443,network:'ws',security:'tls',chain:null},
    {id:3,name:'DE Reality',node:'vps-de',address:'de.example.com',protocol:'vless',port:443,network:'tcp',security:'reality',chain:null},
    {id:4,name:'Home VMess',node:'home',address:'',protocol:'vmess',port:2083,network:'ws',security:'tls',chain:null},
  ],
  admins: [
    {id:1,username:'admin',role:'owner',status:'active',last:Date.now()-5*60e3,self:true},
    {id:2,username:'mila',role:'admin',status:'active',last:Date.now()-3*DAY},
  ],
  settings: {...SETTINGS_DEFAULTS, ...(lsGet(KEY_SAVED) || {})},
  chains: [
    {id:1,name:'FI-DE',hops:[
      {node:'vps-fi',protocol:'vless',network:'tcp',security:'reality',port:2053},
      {node:'vps-de',protocol:'vless',network:'tcp',security:'reality',port:2053}]},
    {id:2,name:'Home-FI-DE',hops:[
      {node:'home',protocol:'vless',network:'tcp',security:'reality',port:443},
      {node:'vps-fi',protocol:'vless',network:'grpc',security:'tls',port:2083},
      {node:'vps-de',protocol:'vless',network:'tcp',security:'reality',port:2083}]},
    {id:3,name:'Home-FI',hops:[
      {node:'home',protocol:'vless',network:'tcp',security:'reality',port:2053},
      {node:'vps-fi',protocol:'vless',network:'tcp',security:'reality',port:2053}]},
  ],
};


/* Хост цепочки — производное от цепочки: название цепочки плюс её входной хоп.
   В mock.hosts таких записей нет: они подсасываются прямо из chains при каждом
   GET /api/hosts, поэтому переименование или удаление цепочки сразу видно в хостах. */
const chainHost = c => {
  const h = c.hops[0];
  return {id:'c'+c.id, name:c.name, node:h.node, protocol:h.protocol, port:h.port,
          network:h.network, security:h.security, chain:c.id, hops:c.hops.length};
};
const hostsView = () => [...mock.hosts, ...mock.chains.map(chainHost)];

async function call(method, path, body){
  if(USE_MOCK) return mockCall(method, path, body);
  const r = await fetch(API_BASE + path, {
    method, headers:{'Content-Type':'application/json','Authorization':'Bearer '+(localStorage.getItem('token')||'')},
    body: body ? JSON.stringify(body) : undefined});
  if(!r.ok){
    // бэкенд отвечает внятным detail на русском — показываем его, а не JSON целиком
    let detail = '';
    try{
      const data = await r.json();
      detail = Array.isArray(data.detail)
        ? data.detail.map(d => `${(d.loc||[]).slice(1).join('.') || 'запрос'}: ${d.msg}`).join('; ')
        : (data.detail || '');
    }catch{ detail = await r.text().catch(()=>''); }
    /* сессия кончилась посреди работы: не прячем это в ошибку, а сразу просим войти */
    if(r.status === 401 && !/^\/api\/(login|fido|me)/.test(path)){ tokenSet(''); meSet(null); stopRefresh(); askLogin(t('auth.required')); }
    throw new Error(detail || `${r.status} ${r.statusText}`);
  }
  return r.status === 204 ? null : r.json();
}
function mockCall(method, path, body){
  const m = path.match(/^\/api\/(\w+)(?:\/(\d+))?(?:\/(\w+))?(?:\/(\d+))?/);
  const kind = m[1], id = +m[2], sub = m[3], subId = +m[4];
  /* Тестовый режим: вход здесь условный — панель под владельцем, ключей нет,
     аппаратный выкопать из браузера в моке нельзя и честно говорим об этом. */
  if(kind==='login') return Promise.resolve({token:'mock-token', admin:{id:1,username:'admin',role:'owner',status:'active',last:Date.now(),self:true,keys:0,sessions:1}});
  if(kind==='me') return Promise.resolve({id:1,username:'admin',role:'owner',expiresAt:Date.now()+DAY,sessions:1});
  if(kind==='logout') return Promise.resolve({ok:true});
  if(kind==='fido') return Promise.reject(new Error('в тестовом режиме аппаратный ключ не проверяется'));
  if(kind==='admins' && sub==='begin') return Promise.reject(new Error('в тестовом режиме браузер не вызывает аппаратный ключ'));
  if(kind==='admins' && sub==='keys'){
    mock.keys = mock.keys || [];
    if(method==='POST'){ const o={id:Date.now(),nickname:body.nickname||'Мок-ключ',algo:'ES256',aaguid:'00000000-0000-0000-0000-000000000000',signCount:0,createdAt:Date.now()}; mock.keys.push(o); return Promise.resolve(o); }
    if(method==='DELETE'){ mock.keys = mock.keys.filter(k=>k.id!==subId); return Promise.resolve(null); }
    return Promise.resolve(mock.keys);
  }
  if(kind==='settings'){
    if(method==='PATCH') Object.assign(mock.settings, body);
    lsSet(KEY_SAVED, mock.settings);            // сохранённые настройки переживают перезагрузку
    return Promise.resolve(mock.settings);
  }
  if(kind==='nodes' && sub==='check') return Promise.resolve(mockNodeCheck(id));
  if(kind==='nodes' && sub==='config'){
    const node = mock.nodes.find(x=>x.id===id) || {};
    const hosts = mock.hosts.filter(h=>!h.chain && h.node===node.name);
    const active = mock.users.filter(u=>u.status==='active');
    const inbounds = hosts.map(h=>{
      const clients = active.map(u=>h.security==='reality'
        ? {password:'••••••••', shortIds:['••••']}
        : {id:'••••••••-••••'});
      const stream = {network:h.network, security:h.security};
      if(h.security==='reality')
        stream.realitySettings = {serverNames:[h.address||'•••'], privateKey:'скрыто панелью'};
      return {tag:'medusa-host-'+h.id, port:h.port, protocol:h.protocol, settings:{clients:clients}, streamSettings:stream};
    });
    return Promise.resolve({config:{log:{loglevel:'warning'}, inbounds:inbounds, outbounds:[{protocol:'freedom',tag:'direct'}]}});
  }
  if(kind==='nodes' && sub==='key'){
    const n = mock.nodes.find(x=>x.id===id);
    return Promise.resolve({key:'sk-api-в-тестовом-режиме-ключ-вымышленный', fingerprint:n?n.fingerprint:null});
  }
  if(body && body.password){ body = {...body}; delete body.password; }   // пароли в мок не кладём
  const list = mock[kind];


  if(method==='GET') return Promise.resolve(kind==='hosts' ? hostsView() : list);
  if(method==='POST'){
    const extra = kind==='users' ? {token:Math.random().toString(36).slice(2,12),status:'active',used:0}
                : kind==='hosts' ? {chain:null}
                : kind==='admins' ? {status:'active',last:0,self:false}
                : kind==='nodes' ? {online:false,users:0,traffic:0,xray:null,apiPort:body.apiPort||9443,apiPath:'/node/health',
                    keySet:!!body.apiKey,fingerprint:body.apiKey?'00000-00000':null,keyMasked:body.apiKey?'sk-api…00000-00000':null,agent:null,seenAt:0} : {};
    const o = {id:Date.now(),...extra,...body};
    list.push(o);
    return Promise.resolve(o);   // хост цепочки появится сам: его отдаёт hostsView()
  }
  const i = list.findIndex(x=>x.id===id);
  if(method==='PATCH') Object.assign(list[i], body);
  if(method==='DELETE') list.splice(i,1);
  return Promise.resolve(list[i]||null);
}

/* Тестовый режим: панель никуда не ходит, поэтому проверка связи честная: «не ходили». */
function mockNodeCheck(id){
  const n = mock.nodes.find(x=>x.id===id);
  return {
    ok:false, reachable:false, keyOk:false, online:!!(n&&n.online),
    panelFingerprint:n?n.fingerprint:null, node:null, checkedAt:Date.now(),
    error:'в тестовом режиме панель никуда не ходит: настоящая проверка связи — только с живой нодой',
    node_row:n||null,
  };
}


/* ---------- Утилиты ---------- */
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = b => { const u = UNITS(); return b >= GB ? (b/GB).toFixed(b>=10*GB?0:1)+' '+u.gb : (b/1048576).toFixed(0)+' '+u.mb; };
function toast(msg){const e=$('#toast');e.textContent=msg;e.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>e.classList.remove('show'),1800)}
const STATUS_CLASS = {active:'b-ok',disabled:'b-off'};
const statusLabel = s => t('status.'+s);
const roleLabel = r => t('role.'+r);
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
  cpu:'<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M11 2.5V7M13 2.5V7M11 17v4.5M13 17v4.5M2.5 11H7M2.5 13H7M17 11h4.5M17 13h4.5"/>',
  ram:'<rect x="3" y="7.5" width="18" height="8.5" rx="1.8"/><path d="M7 11h3M14 11h3"/><path d="M7 16v2.5M12 16v2.5M17 16v2.5"/>',
  disk:'<rect x="3" y="6" width="18" height="12" rx="2.5"/><path d="M3 11h18"/><path d="M6.5 15h.01M9.5 15h.01"/>',
  chev:'<path d="M9 6l6 6-6 6"/>',
  ovpn:'<circle cx="12" cy="9.5" r="3.8"/><path d="M8.2 9.5v7A1.5 1.5 0 0 0 9.7 18h4.6a1.5 1.5 0 0 0 1.5-1.5v-7"/><path d="M12 12.4v2.6"/>',
};
const ic = n => `<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]}</svg>`;
function ago(ts){
  if(!ts) return t('ago.never');
  const m = Math.floor((Date.now()-ts)/60000);
  if(m < 1) return t('ago.now');
  if(m < 60) return t('ago.min',{n:m});
  if(m < 1440) return t('ago.hour',{n:Math.floor(m/60)});
  return t('ago.day',{n:Math.floor(m/1440)});
}

/* ---------- метрики сервера, на котором крутится панель ---------- */
const gb = b => { const u = UNITS(); return b == null ? '—' : b >= GB ? (b/GB).toFixed(b >= 10*GB ? 0 : 1)+' '+u.gb : (b/1048576).toFixed(0)+' '+u.mb; };
const pctText = p => p == null ? '—' : (Math.round(p*10)/10)+'%';
const loadClass = p => p >= 85 ? 'full' : p >= 65 ? 'hi' : '';

/* метрики просим у бэкенда даже в тестовом режиме — они настоящие;
   если бэкенда нет — показываем правдоподобную заглушку */
async function fetchSystem(){
  if(USE_MOCK) return mockSystem();
  return call('GET','/api/system');      // метрики тоже под учёткой: без сессии бэкенд их не отдаёт
}
function mockSystem(){
  const j = (base, spread) => Math.max(0.5, Math.round((base + (Math.random()*2-1)*spread)*10)/10);
  const cpuPct = j(18, 9), memPct = j(42, 12), diskPct = j(31, 6);
  const total = 16*GB, diskTotal = 240*GB;
  return {
    mocked:true,
    hostname:'medusa-server',
    cpu:{percent:cpuPct, cores:8, load1:j(1.2,.6), load5:j(1,.4), load15:j(.9,.3)},
    memory:{total, used:Math.round(total*memPct/100), available:Math.round(total*(100-memPct)/100), percent:memPct, swapTotal:2*GB, swapUsed:Math.round(GB/2)},
    disks:[{mount:'/', device:'/dev/sda1', total:diskTotal, used:Math.round(diskTotal*diskPct/100), free:Math.round(diskTotal*(100-diskPct)/100), percent:diskPct}],
  };
}

function sysCard(icon, title, value, unit, percent){
  return `<div class="syscard">
    <div class="systitle">${ic(icon)}${esc(title)}</div>
    <b class="sysval">${esc(value)}${unit?` <small>${esc(unit)}</small>`:''}</b>
    <div class="bar"><i class="${percent == null ? '' : loadClass(percent)}" style="width:${percent == null ? 0 : Math.max(1,Math.min(100,percent))}%"></i></div>
  </div>`;
}

function sysInner(sys){
  if(!sys) return '';
  const c = sys.cpu || {}, m = sys.memory || {};
  const cards = [];
  cards.push(sysCard('cpu', t('sys.cpu'), pctText(c.percent), null, c.percent));
  if(m.total)
    cards.push(sysCard('ram', t('sys.ram'), gb(m.used), `/ ${gb(m.total)}`, m.percent));
  for(const d of (sys.disks || []))
    cards.push(sysCard('disk', d.mount === '/' ? t('sys.disk') : t('sys.diskMount',{mount:d.mount}), gb(d.used), `/ ${gb(d.total)}`, d.percent));
  return cards.join('');
}

const sysStamp = sys => sys.mocked ? t('sys.mocked',{time:timeStr(new Date())}) : t('sys.updated',{time:timeStr(new Date())});

function sysSection(sys){
  if(!sys) return `<div class="panel"><div class="empty">${t('sys.unavailable')}</div></div>`;
  return `<section class="grp"><div class="sect">
      <h3>${ic('server')}${t('sys.server')}<span class="count">${esc(sys.hostname || '')}</span></h3>
      <span class="syslive${sys.mocked?' off':''}" id="sysnote">${sysStamp(sys)}</span>
    </div>
    <div class="sys" id="sysgrid">${sysInner(sys)}</div>
  </section>`;
}

/* Панель опрашивает ноды сама (src/panel/poller.py), но человек смотрит на страницу, а не
   на базу. Поэтому открытая страница перечитывается с тем же интервалом из настроек
   («Опрос нод») — статус ноды, версии и время последней проверки меняются сами, без
   перезагрузки. Правила тишины: не трогать страницу с формой настроек, не трогать,
   пока открыто окно правки или пока пользователь что-то печатает, и не работать в фоне. */
let refreshTimer = null;
const refreshMs = () => Math.max(5, (savedSettings && savedSettings.pollInterval) || 30) * 1000;
function stopRefresh(){ if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; } }
function startRefresh(){ stopRefresh(); refreshTimer = setInterval(autoRefresh, refreshMs()); }

async function autoRefresh(){
  if(document.hidden) return;
  if(document.querySelector('dialog[open]')) return;      // открытое окно правит человек
  if(page === 'settings') return;                          // там черновик формы, не перерисовывать под руками
  const typing = document.activeElement;
  if(typing && typing.matches('#view input, #view select, #view textarea')) return;
  const view = $('#view'), keepScroll = view ? view.scrollTop : 0;
  try{ await show(page); }
  catch(err){ /* панель могла перезагрузиться — попробуем в следующий круг */ }
  const again = $('#view'); if(again) again.scrollTop = keepScroll;
}

/* ---------- «поток» трафика по нодам на обзоре ----------
   Не таблица, а распределение: сверху общая полоса, разрезанная на доли каждой ноды,
   ниже — строки нод со своим цветом, полосой относительно самой загруженной ноды,
   долей от общего трафика и счётчиком пользователей. */
const NODE_HUES = [198, 158, 40, 342, 266, 92];   // подобранные оттенки: лазурный, зелёный, янтарный, розовый, фиолетовый, салатовый
const nodeHue = i => NODE_HUES[i % NODE_HUES.length];
const nodeColor = i => `hsl(${nodeHue(i)} 68% 52%)`;

function nodesBlock(nodes, total){
  if(!nodes.length) return `<div class="panel"><div class="empty">${t('empty.nodes')}</div></div>`;
  const max = Math.max(...nodes.map(n => n.traffic), 1);
  const bar = nodes.map((n,i)=>{
    const share = total > 0 ? n.traffic / total * 100 : 100 / nodes.length;
    return `<i title="${esc(n.name)} — ${fmt(n.traffic)}" style="--nc:${nodeColor(i)};width:${Math.max(share, 1.2)}%"></i>`;
  }).join('');
  const legend = nodes.map((n,i)=>`<span class="lgd"><i style="--nc:${nodeColor(i)}"></i>${esc(n.name)}</span>`).join('');
  const rows = nodes.map((n,i)=>{
    const share = total > 0 ? Math.round(n.traffic / total * 100) : 0;
    return `<div class="flowrow${n.online?'':' off'}" style="--nc:${nodeColor(i)}">
      <span class="fdot"></span>
      <div class="fmeta"><b>${esc(n.name)}</b><span class="mono">${esc(n.address)}</span></div>
      <div class="fbar"><i style="width:${Math.max(2, n.traffic / max * 100)}%"></i></div>
      <div class="fnums"><b${n.trafficError?` class="fstale" title="${esc(n.trafficError)}"`:''}>${fmt(n.traffic)}</b><span${n.trafficError?' class="fstale"':''}>${n.trafficError?t('overview.trafficStale'):t('overview.share',{p:share})}</span></div>
      <div class="fusers" title="${t('th.users')}">${ic('users')}<b>${n.users}</b></div>
      <span class="badge ${n.online?'b-ok':'b-bad'}">${n.online?t('node.online'):t('node.offline')}</span>
    </div>`;
  }).join('');
  return `<section class="grp">
    <div class="sect"><h3>${ic('activity')}${t('overview.nodesTraffic')}<span class="count">${fmt(total)}</span></h3>
      <div class="legend">${legend}</div></div>
    <div class="panel flow">
      <div class="flowbar">${bar}</div>
      <div class="flowrows">${rows}</div>
    </div>
  </section>`;
}

/* ---------- приложения клиентов: та же статистика, но в радиальном виде ----------
   Кольцо разрезано на доли каждого клиента, по центру — всего подписок,
   ниже список строк с объёмом трафика, долей и счётчиком активных. */
const CLIENTS = {
  happ:{label:'Happ', hue:266},
  'clash-meta':{label:'Clash Meta', hue:198},
  'clash-verge':{label:'Clash Verge', hue:158},
  v2rayng:{label:'v2rayNG', hue:40},
  hiddify:{label:'Hiddify', hue:342},
  shadowrocket:{label:'Shadowrocket', hue:92},
  streisand:{label:'Streisand', hue:120},
  unknown:{label:null, hue:222},
};
const clientOf = u => (u.client && CLIENTS[u.client]) ? u.client : 'unknown';
const clientLabel = k => (CLIENTS[k] && CLIENTS[k].label) || t('client.unknown');
const clientColor = k => `hsl(${(CLIENTS[k] || CLIENTS.unknown).hue} 68% 52%)`;
const subsWord = n => plural(n, t('subs.one'), t('subs.few'), t('subs.many'));

function clientsStats(users){
  const map = new Map();
  for(const u of users){
    const k = clientOf(u);
    const s = map.get(k) || {key:k, count:0, active:0, traffic:0};
    s.count++;
    s.active += u.status === 'active' ? 1 : 0;
    s.traffic += u.used || 0;
    map.set(k, s);
  }
  const list = [...map.values()];
  const totalSubs = list.reduce((a,s)=>a+s.count, 0) || 1;
  const totalTraffic = list.reduce((a,s)=>a+s.traffic, 0) || 1;
  for(const s of list){
    s.shareSubs = s.count / totalSubs * 100;
    s.shareTraffic = s.traffic / totalTraffic * 100;
  }
  list.sort((a,b) => b.count - a.count || b.traffic - a.traffic);
  return {list, totalSubs, totalTraffic};
}

function clientsBlock(users){
  if(!users.length) return '';
  const {list, totalSubs, totalTraffic} = clientsStats(users);
  const R = 56, SW = 16, C = 2 * Math.PI * R, GAP = 4;
  let acc = 0;
  const segs = list.map((s,i)=>{
    const len = Math.max(C * s.shareSubs / 100 - GAP, 2);
    const seg = `<circle class="seg" style="--cc:${clientColor(s.key)};--c:${C};--i:${i}" cx="70" cy="70" r="${R}" fill="none" stroke="var(--cc)" stroke-width="${SW}" stroke-dasharray="${len.toFixed(2)} ${(C-len).toFixed(2)}" stroke-dashoffset="${(-acc).toFixed(2)}"><title>${esc(clientLabel(s.key))} — ${s.count} ${subsWord(s.count)}</title></circle>`;
    acc += len + GAP;
    return seg;
  }).join('');
  const legend = list.map(s=>`<span class="lgd"><i style="--nc:${clientColor(s.key)}"></i>${esc(clientLabel(s.key))}</span>`).join('');
  const rows = list.map((s,i)=>`<div class="clrow" style="--nc:${clientColor(s.key)}">
      <span class="fdot"></span>
      <div class="fmeta"><b>${esc(clientLabel(s.key))}</b><span class="mono">${s.count} ${subsWord(s.count)}</span></div>
      <div class="fnums"><b>${fmt(s.traffic)}</b><span>${t('overview.share',{p:Math.round(s.shareTraffic)})}</span></div>
      <div class="fusers" title="${t('clients.activeTitle')}">${ic('power')}<b>${s.active}</b></div>
      <span class="badge ${s.active?'b-ok':'b-off'}">${Math.round(s.shareSubs)}%</span>
    </div>`).join('');
  return `<section class="grp">
    <div class="sect"><h3>${ic('users')}${t('overview.clients')}<span class="count">${totalSubs} ${subsWord(totalSubs)}</span></h3>
      <div class="legend">${legend}</div></div>
    <div class="panel clients">
      <div class="donutwrap">
        <svg class="donut" viewBox="0 0 140 140" role="img" aria-label="${t('overview.clientsAria')}">${segs}</svg>
        <div class="donutmid"><b>${totalSubs}</b><span>${subsWord(totalSubs)}</span></div>
      </div>
      <div class="clrows">${rows}</div>
    </div>
  </section>`;
}

/* ---------- Страницы ---------- */

const pages = {
  async overview(){
    const [users,nodes,chains] = await Promise.all([call('GET','/api/users'),call('GET','/api/nodes'),call('GET','/api/chains')]);
    const sys = await fetchSystem().catch(()=>null);
    const act = users.filter(u=>u.status==='active').length;
    const total = nodes.reduce((a,n)=>a+n.traffic,0);
    const on = nodes.filter(n=>n.online).length;
    return `<div class="head"><h2>${t('overview.title')}</h2></div>
      <div class="stats">
        <div class="stat"><i class="chip">${ic('users')}</i><b>${act} / ${users.length}</b><span>${t('stat.activeUsers')}</span></div>
        <div class="stat"><i class="chip">${ic('server')}</i><b>${on} / ${nodes.length}</b><span>${t('stat.nodesOnline')}</span></div>
        <div class="stat"><i class="chip">${ic('activity')}</i><b>${fmt(total)}</b><span>${t('stat.traffic')}</span></div>
        <div class="stat"><i class="chip">${ic('link')}</i><b>${chains.length}</b><span>${t('stat.chains')}</span></div>
      </div>
      ${sysSection(sys)}
      ${nodesBlock(nodes, total)}
      ${clientsBlock(users)}`;
  },
  async users(){
    const users = await call('GET','/api/users');
    const w = canWrite();
    const rows = users.map(u=>{const c = STATUS_CLASS[u.status] || STATUS_CLASS.disabled; return `<tr>
      <td><div class="who"><span class="ava">${esc((String(u.name||'').trim()[0]||'?').toUpperCase())}</span><div>${esc(u.name)}<div class="mono">${esc(u.token)} · ${esc(clientLabel(clientOf(u)))}</div></div></div></td>
      <td><span class="badge ${c}">${statusLabel(u.status)}</span></td>
      <td>${fmt(u.used)}</td>
      <td><div class="acts">
        <button class="btn sm" data-a="copy" data-id="${u.id}">${ic('copy')}${t('btn.subscription')}</button>
        ${w?`<button class="btn sm" data-a="toggle" data-id="${u.id}">${ic('power')}${u.status==='disabled'?t('btn.enable'):t('btn.disable')}</button>
        <button class="btn sm del" data-a="del" data-id="${u.id}">${ic('trash')}${t('btn.delete')}</button>`:''}
      </div></td></tr>`}).join('');
    return `<div class="head"><h2>${t('nav.users')}</h2>${w?`<button class="btn pri" data-a="new">${ic('plus')}${t('btn.add')}</button>`:''}</div>
      <div class="panel">${users.length?`<table><thead><tr><th>${t('th.name')}</th><th>${t('th.status')}</th><th>${t('th.traffic')}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
      :`<div class="empty">${t('empty.users')}</div>`}</div>`;
  },
  async nodes(){
    const nodes = await call('GET','/api/nodes');
    const cards = nodes.map(n=>`<div class="node" data-a="nedit" data-id="${n.id}" role="button" tabindex="0">
      <h3>${esc(n.name)}<span class="badge ${n.online?'b-ok live':'b-bad'}">${n.online?t('node.online'):t('node.offline')}</span></h3>
      <div class="mono">${esc(n.address)}:${n.apiPort}</div>
      ${n.applyError?`<div class="nerr" title="${esc(n.applyError)}">${esc(n.applyError)}</div>`:''}
      <dl>
        <dt>${t('node.version')}</dt><dd>${n.agent?esc(n.agent):`<span class="mono">${t('node.notReported')}</span>`}</dd>
        <dt>${t('node.xray')}</dt><dd>${n.xray?esc(n.xray):`<span class="mono">${t('node.notReported')}</span>`}</dd>
      </dl>
      <span class="nopen">${t('node.openTip')}${ic('chev')}</span>
    </div>`).join('');
    return `<div class="head"><h2>${t('nav.nodes')}</h2>${canWrite()?`<button class="btn pri" data-a="newnode">${ic('plus')}${t('btn.newNode')}</button>`:''}</div>` +
      (nodes.length ? `<div class="nodes">${cards}</div>` : `<div class="panel"><div class="empty">${t('empty.nodes')}</div></div>`);
  },
  async hosts(){
    const [hosts,chains] = await Promise.all([call('GET','/api/hosts'),call('GET','/api/chains')]);
    const sec = {none:'b-off',tls:'b-ok',reality:'b-ok'};
    const cmap = Object.fromEntries(chains.map(c=>[c.id,c]));
    const direct = hosts.filter(h=>!h.chain), viaChain = hosts.filter(h=>h.chain), w = canWrite();
    const cfg = h=>`<td><span class="badge b-proto">${esc(PROTO[h.protocol]||h.protocol)}</span></td><td>${h.port}</td><td>${esc(h.network)}</td>
      <td><span class="badge ${sec[h.security]}">${esc(h.security)}</span></td>`;
    const route = h=>{ const c = cmap[h.chain]; return c ? `<span class="route">${c.hops.map(x=>esc(x.node)).join(ic('chev'))}</span>` : esc(h.node); };
    const group = (icon,title,n,btn,inner)=>`<section class="grp"><div class="sect"><h3>${ic(icon)}${title}<span class="count">${n}</span></h3>${btn}</div>${inner}</section>`;
    const dRows = direct.map(h=>`<tr><td>${esc(h.name)}</td><td>${h.address?esc(h.address):`<span class="mono">${esc(h.node)}</span>`}</td><td>${esc(h.node)}</td>${cfg(h)}
      <td><div class="acts">${w?`<button class="btn sm" data-a="hedit" data-id="${h.id}">${ic('gear')}${t('btn.edit')}</button><button class="btn sm del" data-a="hdel" data-id="${h.id}">${ic('trash')}${t('btn.delete')}</button>`:''}</div></td></tr>`).join('');
    const cRows = viaChain.map(h=>`<tr><td>${esc(h.name)}</td><td>${route(h)}</td>${cfg(h)}
      <td><div class="acts"><button class="btn sm" data-a="gochain">${ic('link')}${t('btn.chain')}</button></div></td></tr>`).join('');
    const tbl = (heads,rows,empty)=>`<div class="panel">${rows?`<table><thead><tr>${heads.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">${empty}</div>`}</div>`;
    const cols = [t('cfg.protocol'),t('cfg.port'),t('cfg.transport'),t('cfg.security'),''];
    return `<div class="head"><h2>${t('nav.hosts')}</h2></div>`+
      group('globe',t('hosts.direct'),direct.length,w?`<button class="btn pri" data-a="newhost">${ic('plus')}${t('btn.newHost')}</button>`:'',
        tbl([t('th.title'),t('th.address'),t('th.node'),...cols],dRows,t('empty.direct')))+
      group('link',t('hosts.viaChains'),viaChain.length,w?`<button class="btn pri" data-a="newchain">${ic('plus')}${t('btn.newChain')}</button>`:'',
        tbl([t('th.title'),t('th.route'),...cols],cRows,t('empty.viaChain')));
  },
  async admins(){
    const list = await call('GET','/api/admins');
    /* кому доступна строка: владельца не трогает никто, свои пределы у администратора —
       только своя учётка */
    const reachable = a => a.self || (canManage() && a.role !== 'owner');
    const rows = list.map(a=>`<tr>
        <td><div class="who"><span class="ava">${esc(a.username[0].toUpperCase())}</span><div>${esc(a.username)}${a.self?` <span class="badge b-off">${t('role.self')}</span>`:''}</div></div></td>
        <td><span class="badge ${a.role==='owner'?'b-proto':'b-off'}">${roleLabel(a.role)}</span></td>
        <td><span class="badge ${a.status==='active'?'b-ok':'b-off'}">${statusLabel(a.status)}</span></td>
        <td>${ago(a.last)}</td>
        <td><div class="acts">${reachable(a)?`<button class="btn sm" data-a="aedit" data-id="${a.id}">${ic('gear')}${t('btn.edit')}</button>`:''}</div></td></tr>`).join('');
    return `<div class="head"><h2>${t('nav.admins')}</h2>${canManage()?`<button class="btn pri" data-a="anew">${ic('plus')}${t('btn.add')}</button>`:''}</div>
      <div class="panel"><table><thead><tr><th>${t('th.login')}</th><th>${t('th.role')}</th><th>${t('th.status')}</th><th>${t('th.lastLogin')}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  },
  async settings(){
    try{ savedSettings = {...savedSettings, ...(await call('GET','/api/settings'))}; }catch(e){ toast(t('toast.loadSettings',{msg:e.message})) }
    setDraft(diffSettings(settingsNow()));      // отбрасываем то, что уже совпадает с сохранённым
    const s = settingsNow();
    const field = (title,hint,input)=>`<div class="field"><div><div class="ft">${title}</div><div class="sub">${hint}</div></div>${input}</div>`;
    const inp = (name,val,extra='')=>`<input name="${name}" value="${esc(val)}" ${extra}>`;
    const num = (name,val,min,max)=>inp(name,val,`type="number" min="${min}" max="${max}" required`);
    const themes = {auto:t('theme.auto'),light:t('theme.light'),dark:t('theme.dark')};
    const theme = `<select name="theme" >${Object.entries(themes).map(([k,v])=>`<option value="${k}" ${k===s.theme?'selected':''}>${v}</option>`).join('')}</select>`;
    /* галочка настройки рисуется сама (см. style.css): квадрат в языке панели,
       галочка — штрихом, а не системной галочкой браузера */
    const passkey = `<input name="passkeyEnabled" type="checkbox" ${s.passkeyEnabled?'checked':''}>`;
    const session = me && me.expiresAt ? ` · ${t('settings.sessionUntil',{time:timeStr(new Date(me.expiresAt))})}` : '';
    return `<div class="head"><h2>${t('settings.title')}</h2></div>
      <form id="sform" class="sform" autocomplete="off">
        <div class="panel pad"><h3 class="sh">${ic('gear')}${t('settings.general')}</h3>
          ${field(t('settings.panelName'),t('settings.panelName.hint'),inp('panelName',s.panelName,'required maxlength="32"'))}
          ${field(t('settings.theme'),t('settings.theme.hint'),theme)}
        </div>
        <div class="panel pad"><h3 class="sh">${ic('link')}${t('settings.subs')}</h3>
          ${field(t('settings.subUrl'),t('settings.subUrl.hint'),inp('subUrl',s.subUrl,'type="url" required placeholder="http://127.0.0.1:8000/sub"'))}
          ${field(t('settings.subTitle'),t('settings.subTitle.hint'),inp('subTitle',s.subTitle,'required maxlength="48"'))}
          ${field(t('settings.subInterval'),t('settings.subInterval.hint'),num('subInterval',s.subInterval,1,168))}
        </div>
        <div class="panel pad"><h3 class="sh">${ic('server')}${t('settings.nodes')}</h3>
          ${field(t('settings.pollInterval'),t('settings.pollInterval.hint'),num('pollInterval',s.pollInterval,5,3600))}
          ${field(t('settings.nodeTimeout'),t('settings.nodeTimeout.hint'),num('nodeTimeout',s.nodeTimeout,2,120))}
        </div>
        <div class="panel pad"><h3 class="sh">${ic('shield')}${t('settings.security')}</h3>
          ${field(t('settings.sessionHours'),t('settings.sessionHours.hint')+session,num('sessionHours',s.sessionHours,1,720))}
          ${field(t('settings.passkey'),t('settings.passkey.hint'),passkey)}
        </div>
        <div class="savebar">
          <span class="note" id="snote" ${draft?'':'hidden'}>${t('settings.unsaved')}</span>
          <button type="button" class="btn" id="scancel" data-a="sdiscard" ${draft?'':'hidden'}>${t('btn.discard')}</button>
          <button class="btn pri" id="ssave" ${draft?'':'disabled'}>${ic('check')}${t('btn.save')}</button>
        </div>
      </form>`;
  },
  async chains(){
    const [chains,nodes] = await Promise.all([call('GET','/api/chains'),call('GET','/api/nodes')]);
    const on = Object.fromEntries(nodes.map(n=>[n.name,n.online]));
    const naddr = Object.fromEntries(nodes.map(n=>[n.name,n.address]));
    const word = n=>`${n} ${plural(n, t('hops.one'), t('hops.few'), t('hops.many'))}`;
    const cfg = h=>[PROTO[h.protocol]||h.protocol, h.network!=='tcp'?h.network:'', h.security!=='none'?h.security:''].filter(Boolean).join(' ');
    // адрес хопа показывается явно: свой адрес хоста или адрес его ноды, если своего нет
    const where = h=>`${h.address || naddr[h.node] || ''}:${h.port}`;
    const items = chains.map(c=>{
      const problem = c.hops.some(h=>!(h.node in on)) ? t('chain.nodeRemoved') : c.hops.some(h=>!on[h.node]) ? t('chain.nodeDown') : null;
      const path = c.hops.map((h,k)=>(k?'<div class="link'+(problem?' dead':'')+'"></div>':'')+
        `<div><div class="pill ${on[h.node]?'':'off'}"><b>${esc(h.node)}</b><div class="mono">${esc(cfg(h))}</div><div class="mono">${esc(where(h))}</div></div>
         <div class="sub" style="text-align:center">${k===0?t('chain.entry'):k===c.hops.length-1?t('chain.exit'):t('chain.transit')}</div></div>`).join('');
      return `<div class="chain"><div class="meta"><b>${esc(c.name)}</b><div class="sub">${word(c.hops.length)}</div></div>
        <div class="path">${path}</div>
        <span class="badge ${problem?'b-bad':'b-ok'}">${problem||t('chain.ok')}</span>
        ${canWrite()?`<button class="btn sm" data-a="cedit" data-id="${c.id}">${ic('gear')}${t('btn.edit')}</button>
        <button class="btn sm del" data-a="cdel" data-id="${c.id}">${ic('trash')}${t('btn.delete')}</button>`:''}</div>`}).join('');
    return `<div class="head"><h2>${t('nav.chains')}</h2>${canWrite()?`<button class="btn pri" data-a="newchain">${ic('plus')}${t('btn.newChain')}</button>`:''}</div>`+
      (chains.length?`<div class="chains">${items}</div>`
      :`<div class="panel"><div class="empty">${t('empty.chains')}</div></div>`);
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

let renderSeq = 0;
async function show(p){
  const animate = !reduced && (first || (p && p !== page));
  first = false;
  page = p || page;
  /* номер круга: пока страница ждала ответ, мог начаться более поздний круг (клик по вкладке
     или автосвежение). Поздний круг не должен затирать результат раннего. */
  const seq = ++renderSeq;
  document.querySelectorAll('aside a').forEach(a=>a.classList.toggle('on',a.dataset.p===page));
  moveInd();
  const v = $('#view');
  try{
    const html = await pages[page]();
    if(seq !== renderSeq) return;
    v.innerHTML = html;
  }
  catch(e){
    if(seq !== renderSeq) return;
    v.innerHTML = `<div class="empty">${t('err.load',{msg:esc(e.message)})}</div>`;
  }
  if(page==='settings') syncSettingsUI();
  v.dataset.page = page;              // какая страница действительно отрендерена (по этому ориентируются UI-проверки)
  v.classList.toggle('enter', animate);
  if(animate){
    v.querySelectorAll('.stat,.node,.chain,tbody tr,.pad,.sect,.flowrow,.clrow').forEach((el,i)=>el.style.setProperty('--i',Math.min(i,12)));
    v.querySelectorAll('.stat b').forEach(countUp);
  }
}

/* ---------- События ---------- */
document.querySelector('aside').addEventListener('click', e=>{ const a = e.target.closest('a[data-p]'); if(a) show(a.dataset.p); });
document.addEventListener('keydown', e=>{
  if(e.key!=='Enter' && e.key!==' ') return;
  const card = document.activeElement;
  if(card && card.matches('#view [role="button"][data-a]')){ e.preventDefault(); card.click(); }
});
$('#view').addEventListener('click', async e=>{
  const b = e.target.closest('[data-a]'); if(!b) return;
  const a = b.dataset.a, id = +b.dataset.id;
  /* диалог своей учётки нужен всякому вошедшему: пароль, свои ключи;
     а бэкенд и так не пропустит правку чужого */
  const WRITE_ACTIONS = ['new','newnode','newhost','newchain','anew','del','toggle','hdel','hedit','cedit','cdel','atoggle','adel','ncheck','ndelete'];
  if(WRITE_ACTIONS.includes(a) && !canWrite()) return toast(t('auth.required'));
  try{
    if(a==='new'){ $('#dlg').returnValue=''; return $('#dlg').showModal(); }
    /* return без await: ошибка диалога ушла бы мимо try/catch и в консоль вместо объяснения */
    if(a==='newchain') return void await openChain();
    if(a==='cedit') return void await openChainEdit(id);
    if(a==='newhost') return void await openHost();
    if(a==='gochain') return void await show('chains');
    if(a==='newnode') return void await openNode();
    if(a==='nedit') return void await openNodeEdit(id);
    if(a==='anew') return void await openAdmin();
    if(a==='aedit') return openAdminEdit(id);
    if(a==='sdiscard') return discardDraft();
    if(a==='hdel'){ if(!confirm(t('confirm.delHost'))) return; await call('DELETE','/api/hosts/'+id); toast(t('toast.deleted')); return show(); }
    if(a==='hedit') return openHostEdit(id);
    if(a==='cdel'){ if(!confirm(t('confirm.delChain'))) return; await call('DELETE','/api/chains/'+id); toast(t('toast.chainDeleted')); return show(); }
    if(a==='copy'){
      const u = (await call('GET','/api/users')).find(x=>x.id===id);
      if(await copyText(SUB_BASE + u.token)) toast(t('toast.subCopied'));
      else prompt(SUB_BASE + u.token);
      return;
    }
    if(a==='toggle'){
      const u = (await call('GET','/api/users')).find(x=>x.id===id);
      await call('PATCH','/api/users/'+id,{status:u.status==='disabled'?'active':'disabled'});
    }
    if(a==='del'){ if(!confirm(t('confirm.delUser'))) return; await call('DELETE','/api/users/'+id); toast(t('toast.deleted')); }
    show();
  }catch(err){ toast(t('toast.error',{msg:err.message})) }
});
$('#dlg').addEventListener('close', async ()=>{
  if($('#dlg').returnValue!=='ok') return;
  const f = new FormData($('#uform'));
  try{
    await call('POST','/api/users',{name:f.get('name')});
    toast(t('toast.userCreated')); $('#uform').reset(); show('users');
  }catch(err){ toast(t('toast.error',{msg:err.message})) }
});

/* ----- общие настройки инбаунда: протокол / транспорт / защита / порт ----- */
const PROTOS = ['vless','vmess','trojan','ss'];
const SEC_BY = {vless:['none','tls','reality'],vmess:['none','tls'],trojan:['tls','reality'],ss:['none']};
const opts = (list,label)=>list.map(v=>`<option value="${v}">${esc(label?label[v]:v)}</option>`).join('');
const cfgHTML = ()=>`<div class="cfgwrap"><div class="cfgh"><span>${t('cfg.protocol')}</span><span>${t('cfg.transport')}</span><span>${t('cfg.security')}</span><span>${t('cfg.port')}</span></div>
  <div class="cfg"><select data-k="protocol" aria-label="${t('cfg.protocol')}">${opts(PROTOS,PROTO)}</select>
  <select data-k="network" aria-label="${t('cfg.transport')}">${opts(['tcp','ws','grpc'])}</select>
  <select data-k="security" aria-label="${t('cfg.security')}">${opts(['none','tls','reality'])}</select>
  <input data-k="port" type="number" min="1" max="65535" required placeholder="${t('cfg.port')}" aria-label="${t('cfg.port')}"></div></div>`;
const K = (root,k)=>root.querySelector(`[data-k="${k}"]`);
function syncCfg(root){
  const sec = K(root,'security'), net = K(root,'network'), proto = K(root,'protocol').value, ok = SEC_BY[proto];
  [...sec.options].forEach(o=>o.disabled = !ok.includes(o.value));
  if(!ok.includes(sec.value)) sec.value = ok[0];
  [...net.options].forEach(o=>o.disabled = (sec.value==='reality' && o.value==='ws') || (proto==='ss' && o.value!=='tcp'));
  if(net.selectedOptions[0].disabled) net.value = [...net.options].find(o=>!o.disabled).value;
}
function initCfg(root, onChange){
  K(root,'security').value = 'none'; syncCfg(root);
  if(onChange) onChange();
  /* слушаем не сам cfgwrap: поля защиты живут в соседнем контейнере (#hsec),
     а реагируют на смену протокола/защиты в cfgwrap — общий родитель удобней */
  (root.parentElement || root).addEventListener('change', e=>{
    if(e.target.matches('[data-k="protocol"],[data-k="security"],[data-k="network"]')){ syncCfg(root); if(onChange) onChange(); }
  });
}
const readCfg = root => ({protocol:K(root,'protocol').value, network:K(root,'network').value, security:K(root,'security').value, port:+K(root,'port').value});

/* ----- поля защиты: они появляются только тогда, когда защита выбрана -----
   reality: маскированный dest (куда нода «притворяется» сайтом) и список sni,
   которые она принимает; tls: sni, свои сертификаты и отношение к чужому SNI.
   Отпечаток клиента живёт в «Дополнительных настройках». У «none» показывать нечего */
const FPS = ['chrome','edge','safari','firefox','android','ios'];
const SEC_FIELDS = {
  reality(h){
    return `<div class="secbox">
      <label><span>${t('cfg.sec.reality.dest')}</span><input data-k="dest" maxlength="63" placeholder="www.microsoft.com:443" value="${esc(h.dest||'')}"></label>
      <label><span>${t('cfg.sec.reality.serverNames')}</span><input data-k="serverNames" maxlength="255" placeholder="vpn.example.net, backup.example.net" value="${esc(h.serverNames||'')}"></label>
      <p class="hint">${esc(t('cfg.sec.reality.hint'))}</p></div>`;
  },
  tls(h){
    return `<div class="secbox">
      <label><span>${t('cfg.sec.tls.sni')}</span><input data-k="sni" maxlength="253" placeholder="vpn.example.net" value="${esc(h.sni||'')}"></label>
      <label><span>${t('cfg.sec.tls.cert')}</span><input data-k="certFile" maxlength="255" placeholder="/etc/ssl/medusa.crt" value="${esc(h.certFile||'')}"></label>
      <label><span>${t('cfg.sec.tls.key')}</span><input data-k="keyFile" maxlength="255" placeholder="/etc/ssl/medusa.key" value="${esc(h.keyFile||'')}"></label>
      <label class="chk"><input type="checkbox" data-k="rejectUnknownSni" ${h.rejectUnknownSni?'checked':''}><span>${esc(t('cfg.sec.tls.rejectSni'))}</span></label>
      <p class="hint">${esc(t('cfg.sec.tls.hint'))}</p></div>`;
  },
};
const secHTML = (sec, h = {}) => (SEC_FIELDS[sec] || (()=>''))(h);
function secBody(cfg, root){
  const sec = K(cfg,'security').value, body = {};
  const val = k => K(root,k) ? K(root,k).value.trim() : '';
  if(sec==='reality'){
    body.dest = val('dest');                            // пустое = «как по умолчанию»
    body.serverNames = val('serverNames');
  } else if(sec==='tls'){
    body.sni = val('sni');
    body.certFile = val('certFile');
    body.keyFile = val('keyFile');
    body.rejectUnknownSni = !!(K(root,'rejectUnknownSni') && K(root,'rejectUnknownSni').checked);
  }
  return body;
}

/* ----- «Настройки транспорта»: свёрнуты по умолчанию и показываются там,
   где есть что настроить: у ws — путь и Host-заголовок, у gRPC — имя сервиса и
   authority, а отпечаток клиента (utls) — при любой шифрующей защите;
   у tcp без шифрования настраивать нечего и блок не появляется */
const ADV_BY = {
  ws: h=>`<label><span>${t('cfg.adv.path')}</span><input data-k="path" maxlength="256" placeholder="/ws" value="${esc(h.path||'')}"></label>
    <label><span>${t('cfg.adv.hostHeader')}</span><input data-k="hostHeader" maxlength="63" placeholder="cdn.example.com" value="${esc(h.hostHeader||'')}"></label>`,
  grpc: h=>`<label><span>${t('cfg.adv.serviceName')}</span><input data-k="serviceName" maxlength="64" placeholder="medusa" value="${esc(h.serviceName||'')}"></label>
    <label><span>${t('cfg.adv.grpc.authority')}</span><input data-k="grpcAuthority" maxlength="63" placeholder="grpc.example.net" value="${esc(h.grpcAuthority||'')}"></label>`,
};
const fpField = h=>`<label><span>${t('cfg.sec.fp')}</span><select data-k="fp">${opts(FPS)}</select></label>`;
const advHTML = (net, h = {}, sec = 'none') => {
  const parts = [];
  if(ADV_BY[net]) parts.push(ADV_BY[net](h));
  if(sec==='tls' || sec==='reality') parts.push(fpField(h));
  return parts.length ? `<details class="adv"><summary>${esc(t('cfg.adv'))}</summary><div class="advf">${parts.join('')}</div></details>` : '';
};
function advBody(cfg, root){
  const net = K(cfg,'network').value, sec = K(cfg,'security').value, body = {};
  if(net==='ws' && K(root,'path')){ body.path = K(root,'path').value.trim(); body.hostHeader = K(root,'hostHeader').value.trim(); }
  else if(net==='grpc' && K(root,'serviceName')){
    body.serviceName = K(root,'serviceName').value.trim();
    body.grpcAuthority = K(root,'grpcAuthority').value.trim();
  }
  if((sec==='tls' || sec==='reality') && K(root,'fp')) body.fp = K(root,'fp').value;
  return body;
}

/* ----- диалог «новая нода»: адрес и версия Xray, остальное соберёт опрос нод позже ----- */
const FV = (root,k) => root.querySelector(`[data-f="${k}"]`).value.trim();
function openNode(){
  $('#nform').reset(); $('#ndlg').returnValue = ''; $('#ndlg').showModal();
}
$('#ndlg').addEventListener('close', async ()=>{
  if($('#ndlg').returnValue!=='ok') return;
  const dlg = $('#ndlg');
  const body = {name:FV(dlg,'name'), address:FV(dlg,'address'), apiKey:FV(dlg,'apiKey')};
  const port = FV(dlg,'apiPort'); if(port) body.apiPort = +port;
  try{
    await call('POST','/api/nodes', body);
    toast(t('toast.nodeCreated')); show();
  }catch(err){ toast(t('toast.error',{msg:err.message})) }
});

/* Карточка ноды — это кнопка: всё остальное живёт здесь, в окне правки ноды. */
let editing = null, edited = false, keyKnown = '';
const NEF = () => document.querySelector('#neform');
const nfill = (k,v) => { const el = NEF().querySelector(`[data-f="${k}"]`); if(el) el.value = v; };
const missing = v => v ? esc(v) : `<span class="mono">${t('node.notReported')}</span>`;
function nodeBadge(online){
  const b = $('#ne_badge');
  b.className = `badge ${online ? 'b-ok live' : 'b-bad'}`;
  b.textContent = online ? t('node.online') : t('node.offline');
}
function nodeStatusLine(text, good){
  const box = $('#ne_status');
  box.textContent = text; box.classList.toggle('bad', !good); box.hidden = false;
}
/* Строка трафика в окне ноды: цифра, а вместо неё — причина, по которой счётчики
   молчали. Нода обязана называть её, а не молча показывать ноль. */
function trafficLine(n){
  const dd = $('#ne_traffic');
  if (!dd) return;
  if (n.trafficError) {
    /* байты, которые нода успела насчитать, остаются: они настоящие. Не хватает только
       свежести — и об этом нода сказала сама */
    dd.innerHTML = `${fmt(n.traffic || 0)} · <span class="warn">${esc(t('node.trafficSilent',
      {why: esc(n.trafficError)}))}</span>`;
    return;
  }
  dd.textContent = fmt(n.traffic || 0);
}

async function openNodeEdit(id){
  const n = (await call('GET','/api/nodes')).find(x => x.id === id);
  if(!n) return toast(t('toast.stale'));
  editing = n; edited = false; keyKnown = '';
  $('#ne_name').textContent = n.name;
  nodeBadge(n.online);
  nfill('name', n.name); nfill('address', n.address); nfill('apiPort', n.apiPort);
  // API-ключ здесь вписан целиком — как адрес и порт: его правят, а не гадают по маске
  /* API-ключ здесь вписан целиком — как адрес и порт: его правят, а не гадают по маске */
  if(n.keySet){
    const r = await call('GET',`/api/nodes/${n.id}/key`);
    keyKnown = r.key; nfill('apiKey', keyKnown);
  } else {
    keyKnown = ''; nfill('apiKey', '');
  }
  $('#ne_key').textContent = n.fingerprint ? t('dlg.nodeEdit.fp', {fp: n.fingerprint}) : t('dlg.nodeEdit.keyMissing');
  $('#ne_agent').innerHTML = missing(n.agent);
  $('#ne_xray').innerHTML = missing(n.xray);
  $('#ne_seen').textContent = n.seenAt ? ago(n.seenAt) : t('node.neverChecked');
  trafficLine(n);
  /* конфиг — свёрнутый просмотр: разворачиваешь, панель показывает то, что сама
     собрала и уже отправила (или собирается отправить). Правок здесь нет: конфиг
     рождается из хостов и пользователей, а не из текстового поля */
  const cfgBox = $('#ne_cfg');
  cfgBox.open = false;
  $('#ne_cfgjson').textContent = t('node.configLoading');
  cfgBox.ontoggle = async () => {
    if(!cfgBox.open) return;
    try{
      const r = await call('GET',`/api/nodes/${n.id}/config`);
      $('#ne_cfgjson').textContent = JSON.stringify(r.config, null, 2);
    }catch(err){ $('#ne_cfgjson').textContent = String(err && err.message || err); }
  };
  const box = $('#ne_status'); box.hidden = true; box.textContent = ''; box.classList.remove('bad');
  $('#nedlg').returnValue = ''; $('#nedlg').showModal();
}
$('#nedlg').addEventListener('click', async e=>{
  const b = e.target.closest('button[data-a]'); if(!b) return;
  const a = b.dataset.a;
  try{
    if(a==='ncheck'){
      const r = await call('POST',`/api/nodes/${editing.id}/check`,{});
      const row = r.node_row || editing;
      $('#ne_agent').innerHTML = missing(row.agent);
      $('#ne_xray').innerHTML = missing(row.xray);
      $('#ne_seen').textContent = row.seenAt ? ago(row.seenAt) : t('node.neverChecked');
      trafficLine(row);
      nodeBadge(row.online);
      if(r.ok) nodeStatusLine(t('node.checkOk',{fp:r.node.fingerprint}), true);
      else nodeStatusLine(t('node.checkBad',{msg:r.error}), false);
      edited = true;                      // нода сообщила про себя новое — список обновим при закрытии
    }
    if(a==='ndelete'){
      if(!confirm(t('confirm.delNode'))) return;
      await call('DELETE','/api/nodes/'+editing.id);
      edited = false;
      $('#nedlg').close();
      toast(t('toast.deleted')); show();
    }
  }catch(err){ nodeStatusLine(t('toast.error',{msg:err.message}), false); }
});
$('#nedlg').addEventListener('close', async ()=>{
  if($('#nedlg').returnValue!=='ok') return edited ? show() : undefined;
  const form = NEF();
  const body = {name:FV(form,'name'), address:FV(form,'address'), apiPort:+FV(form,'apiPort')};
  // API-ключ отправляем только если его правда поменяли: иначе панель сочтёт, что
  // связь надо проверять заново, и нода ложно станет «недоступна»
  const key = FV(form,'apiKey'); if(key && key !== keyKnown) body.apiKey = key;
  try{ await call('PATCH','/api/nodes/'+editing.id, body); toast(t('toast.nodeSaved')); }
  catch(err){ toast(t('toast.error',{msg:err.message})) }
  show();
});


/* ----- занятые порты на ноде (хосты + инбаунды цепочек) ----- */
let ctx = {hosts:[],chains:[],nodes:[]};
async function loadCtx(){
  const [hosts,chains,nodes] = await Promise.all([call('GET','/api/hosts'),call('GET','/api/chains'),call('GET','/api/nodes')]);
  ctx = {hosts,chains,nodes};
}
/* Занятые порты считаются по машине, а не по одной ноде: две ноды с одним адресом — это
   один и тот же сервер, и Xray там падает целиком, если два слушателя взяли один порт.
   API-порт ноды — такой же слушатель на том же адресе. */
const machineNames = node => {
  const self = ctx.nodes.find(n=>n.name===node);
  if(!self) return new Set([node]);
  return new Set(ctx.nodes.filter(n=>n.address===self.address).map(n=>n.name));
};
const taken = node => {
  const onMachine = machineNames(node);
  return new Set([
    ...ctx.nodes.filter(n=>onMachine.has(n.name)).map(n=>n.apiPort),
    ...ctx.hosts.filter(h=>onMachine.has(h.node)).map(h=>h.port),
    ...ctx.chains.flatMap(c=>c.hops.filter(h=>onMachine.has(h.node)).map(h=>h.port)),
  ]);
};
function freePort(node, extra=[]){
  const used = new Set([...taken(node), ...extra]);
  const p = [443,8443,2053,2083,2087,2096].find(x=>!used.has(x));
  if(p) return p;
  let r = 10000 + Math.floor(Math.random()*50000); while(used.has(r)) r++;
  return r;
}
const nodeOptions = ()=>ctx.nodes.map(n=>`<option>${esc(n.name)}</option>`).join('');

/* ----- диалог «хост»: один и тот же и для нового, и для правки -----
   при правке предзаполняется всё, что видно в списке, и пустые поля доп.
   настроек означают «сбросить», а не «оставить как было» */
let hostEditing = null;
const setCfg = (k,v)=>{ const el = K($('#hcfg'),k); if(v!=null && v!=='') el.value = v; };
function renderHostExtras(h){
  const sec = K($('#hcfg'),'security').value, net = K($('#hcfg'),'network').value;
  $('#hsec').innerHTML = secHTML(sec, h);
  $('#hadv').innerHTML = advHTML(net, h, sec);
  if(K($('#hadv'),'fp')) K($('#hadv'),'fp').value = h.fp || 'chrome';
}
function hostDialogShell(){
  $('#hform').reset();
  $('#hdlg').returnValue = '';
  $('#hnode').innerHTML = nodeOptions();
  $('#hcfg').innerHTML = cfgHTML();
}
async function openHost(){
  await loadCtx();
  if(!ctx.nodes.length) return toast(t('toast.noNodes'));
  hostEditing = null;
  hostDialogShell();
  $('#hdlg h3').textContent = t('dlg.host.title');
  $('#hdlg [value=ok]').textContent = t('btn.create');
  initCfg($('#hcfg'), ()=>renderHostExtras({}));
  K($('#hcfg'),'port').value = freePort($('#hnode').value);
  $('#hdlg').showModal();
}
async function openHostEdit(id){
  await loadCtx();
  const h = ctx.hosts.find(x=>x.id===id);
  if(!h) return toast(t('err.notFound'));
  hostEditing = id;
  hostDialogShell();
  $('#hdlg h3').textContent = t('dlg.host.editTitle');
  $('#hdlg [value=ok]').textContent = t('btn.save');
  $('#hform [name=name]').value = h.name;
  $('#hform [name=address]').value = h.address || '';
  $('#hnode').value = h.node;
  initCfg($('#hcfg'), ()=>renderHostExtras(h));
  setCfg('protocol', h.protocol); setCfg('network', h.network); setCfg('security', h.security);
  syncCfg($('#hcfg'));
  K($('#hcfg'),'port').value = h.port;
  renderHostExtras(h);
  $('#hdlg').showModal();
}
$('#hnode').onchange = ()=>{ K($('#hcfg'),'port').value = freePort($('#hnode').value); };
$('#hform').addEventListener('submit', e=>{
  if(e.submitter && e.submitter.value!=='ok') return;
  const port = readCfg($('#hcfg')).port, node = $('#hnode').value;
  const own = hostEditing && ctx.hosts.find(x=>x.id===hostEditing);
  if(own && own.port===port && own.node===node) return;   // свой порт при правке — не конфликт
  if(taken(node).has(port)){ e.preventDefault(); toast(t('toast.portTaken',{port,node})); }
});
$('#hdlg').addEventListener('close', async ()=>{
  if($('#hdlg').returnValue!=='ok') return;
  const base = {name:$('#hform [name=name]').value, node:$('#hnode').value,
                address:($('#hform [name=address]').value||'').trim()||null,
                ...readCfg($('#hcfg')), ...secBody($('#hcfg'), $('#hsec'))};
  try{
    if(hostEditing){
      await call('PATCH','/api/hosts/'+hostEditing, {...base, ...advBody($('#hcfg'), $('#hadv'))});
      toast(t('toast.hostEdited'));
    }else{
      await call('POST','/api/hosts', {...base, ...advBody($('#hcfg'), $('#hadv'))});
      toast(t('toast.hostCreated'));
    }
    show();
  }catch(err){ toast(t('toast.error',{msg:err.message})) }
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
    r.querySelector('.hop span').textContent = i===0 ? t('chain.entry') : i===rows.length-1 ? t('chain.exit') : t('chain.transit');
    r.querySelector('.hop button').disabled = rows.length<=2;
  });
}
function addHop(){
  const box = $('#hops');
  if(box.children.length>=6) return toast(t('chain.maxHops',{n:6}));
  const prev = box.lastElementChild ? rowNode(box.lastElementChild) : null;
  const row = document.createElement('div'); row.className = 'hopbox';
  row.innerHTML = `<div class="hop"><span></span><select data-k="node" aria-label="${t('th.node')}">${nodeOptions()}</select>
    <input data-k="address" class="hopaddr" maxlength="63" spellcheck="false" aria-label="${t('chain.hopAddress')}"
           placeholder="${t('chain.hopAddressPh')}" title="${t('chain.hopAddressHint')}">
    <button type="button" class="btn sm">${t('btn.remove')}</button></div>${cfgHTML()}`;
  const other = ctx.nodes.find(n=>n.name!==prev); if(other) K(row,'node').value = other.name;
  initCfg(row); setHopPort(row);
  K(row,'node').onchange = ()=>setHopPort(row);
  row.querySelector('.hop button').onclick = ()=>{ row.remove(); renumber(); };
  box.append(row); renumber();
}
let chainEditing = null;
function chainShell(){
  chainEditing = null;
  $('#cform').reset(); $('#hops').innerHTML = '';
  $('#cdlg h3').textContent = t('dlg.chain.title');
  $('#cdlg [value=ok]').textContent = t('btn.create');
}
function fillHop(row, hop){
  // hop-ряды не пользуются окном хоста (#hcfg), поэтому значения ставятся напрямую,
  // а уже потом syncCfg приводит защиту/транспорт к выбранному протоколу
  K(row,'node').value = hop.node;
  K(row,'protocol').value = hop.protocol;
  K(row,'network').value = hop.network;
  K(row,'security').value = hop.security;
  syncCfg(row);
  K(row,'port').value = hop.port;
  // адрес хопа рендер подставляет и в outbound соседней ноды, и в ссылку входа цепочки
  K(row,'address').value = hop.address || '';
}
async function openChain(chain){
  await loadCtx();
  if(ctx.nodes.length<2) return toast(t('chain.minNodes'));
  chainShell();
  const hops = chain ? chain.hops : [];
  hops.forEach(hop=>{ addHop(); fillHop(hopRows()[hopRows().length-1], hop); });
  if(!hops.length){ addHop(); addHop(); }
  if(chain){
    chainEditing = chain.id;
    $('#cform [name=name]').value = chain.name;
    $('#cdlg h3').textContent = t('dlg.chain.editTitle');
    $('#cdlg [value=ok]').textContent = t('btn.save');
  }
  $('#cdlg').returnValue = ''; $('#cdlg').showModal();
}
async function openChainEdit(id){
  const chains = await call('GET','/api/chains');
  const c = chains.find(x=>x.id===id);
  if(!c) return toast(t('err.notFound'));
  await openChain(c);
}
$('#addhop').onclick = addHop;
$('#cform').addEventListener('submit', e=>{
  if(e.submitter && e.submitter.value!=='ok') return;
  const rows = hopRows(); let err = null;
  // свои порты при правке цепочки конфликтом не считаются: хопа этой же цепочки
  // занимают их прямо сейчас, и перестановка хопов внутри тех же портов — не занято
  const own = chainEditing ? (ctx.chains.find(c=>c.id===chainEditing)?.hops || []) : [];
  const mine = (node, port) => own.some(h=>h.node===node && h.port===port);
  rows.forEach((r,i)=>{
    const n = rowNode(r), port = rowPort(r);
    if(i && n===rowNode(rows[i-1])) err ||= t('chain.hopSameNode');
    if(!mine(n,port) && taken(n).has(port)) err ||= t('toast.portTaken',{port,node:n});
    if(rows.slice(0,i).some(o=>rowNode(o)===n && rowPort(o)===port)) err ||= t('toast.portDup',{port,node:n});
  });
  if(err){ e.preventDefault(); toast(err); }
});
$('#cdlg').addEventListener('close', async ()=>{
  if($('#cdlg').returnValue!=='ok') return;
  const hops = hopRows().map(r=>({node:rowNode(r), ...readCfg(r),
    address: (K(r,'address').value || '').trim() || null}));
  const id = chainEditing, name = $('#cform [name=name]').value;
  try{
    if(id){ await call('PATCH','/api/chains/'+id,{name,hops}); toast(t('toast.chainEdited')); }
    else{ await call('POST','/api/chains',{name,hops}); toast(t('toast.chainCreated')); }
    show();
  }
  catch(err){ toast(t('toast.error',{msg:err.message})) }
});

/* ----- администраторы ----- */
function openAdmin(){ $('#aform').reset(); $('#adlg').returnValue = ''; $('#adlg').showModal(); }
$('#adlg').addEventListener('close', async ()=>{
  if($('#adlg').returnValue!=='ok') return;
  const f = new FormData($('#aform'));
  try{ await call('POST','/api/admins',{username:f.get('username'),password:f.get('password')}); toast(t('toast.adminCreated')); show(); }
  catch(err){ toast(t('toast.error',{msg:err.message})) }
});

/* ----- настройки панели -----
   Сохранённые настройки (savedSettings) и черновик несохранённых правок (draft) лежат в localStorage.
   Поэтому выбранная тема и остальные значения не теряются ни при переходе на другую страницу,
   ни при перезагрузке. Тема к тому же применяется и сохраняется сразу, без кнопки «Сохранить». */

let savedSettings = {...SETTINGS_DEFAULTS, ...(lsGet(KEY_SAVED) || {})};
let draft = lsGet(KEY_DRAFT) || null;

const settingsNow = () => ({...savedSettings, ...(draft || {})});
const sameVal = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const toNum = (v, fallback) => { const n = Number(v); return Number.isFinite(n) ? n : fallback; };

function readSettingsForm(form){
  const f = new FormData(form);
  return {
    panelName: (f.get('panelName') || '').trim() || SETTINGS_DEFAULTS.panelName,
    theme: f.get('theme') || 'auto',
    subUrl: (f.get('subUrl') || '').trim().replace(/\/+$/,''),
    subTitle: (f.get('subTitle') || '').trim() || SETTINGS_DEFAULTS.subTitle,
    subInterval: toNum(f.get('subInterval'), savedSettings.subInterval),
    pollInterval: toNum(f.get('pollInterval'), savedSettings.pollInterval),
    nodeTimeout: toNum(f.get('nodeTimeout'), savedSettings.nodeTimeout),
    sessionHours: toNum(f.get('sessionHours'), savedSettings.sessionHours),
    passkeyEnabled: f.get('passkeyEnabled') === 'on',
  };
}

/* что из введённого действительно отличается от уже сохранённого */
function diffSettings(vals){
  return Object.fromEntries(Object.keys(SETTINGS_DEFAULTS)
    .filter(k => !sameVal(vals[k], savedSettings[k])).map(k => [k, vals[k]]));
}

function setDraft(d){
  draft = d && Object.keys(d).length ? d : null;
  if(draft) lsSet(KEY_DRAFT, draft); else lsDel(KEY_DRAFT);
  syncSettingsUI();
}

function applyTheme(theme){
  const root = document.documentElement;
  if(theme === 'light' || theme === 'dark') root.dataset.theme = theme; else delete root.dataset.theme;
}

function applySettings(s){
  if(!s) return;
  const name = s.panelName || SETTINGS_DEFAULTS.panelName;
  $('#pname').textContent = name;
  document.title = name;
  applyTheme(s.theme || 'auto');
  if(s.subUrl) SUB_BASE = s.subUrl.replace(/\/+$/,'') + '/';
}

/* предпросмотр: название и тема меняются сразу, как только их выбрали */
const previewSettings = () => applySettings(settingsNow());

function syncSettingsUI(){
  const save = $('#ssave'), note = $('#snote'), cancel = $('#scancel'), flag = $('#draftFlag');
  if(save) save.disabled = !draft;
  if(note) note.hidden = !draft;
  if(cancel) cancel.hidden = !draft;
  if(flag) flag.hidden = !draft;
  const link = document.querySelector('aside a[data-p="settings"]');
  if(link){
    if(draft){ link.dataset.dirty = '1'; link.title = t('footer.unsaved.title'); }
    else{ link.removeAttribute('data-dirty'); link.removeAttribute('title'); }
  }
}

/* тема — настройка вида: применяем сразу и сохраняем сразу (локально + на сервере) */
async function persistTheme(theme){
  applyTheme(theme);
  setDraft(diffSettings({...settingsNow(), theme}));
  if(savedSettings.theme === theme) return;
  try{
    savedSettings = {...savedSettings, ...(await call('PATCH','/api/settings',{theme}))};
    lsSet(KEY_SAVED, savedSettings);
  }catch(err){ toast(t('toast.themeLocal',{msg:err.message})) }
  setDraft(diffSettings(settingsNow()));
  previewSettings();
}

function discardDraft(){
  setDraft(null);
  applySettings(savedSettings);
  toast(t('toast.discarded'));
  show('settings');
}

async function saveSettings(vals){
  savedSettings = {...SETTINGS_DEFAULTS, ...savedSettings, ...(await call('PATCH','/api/settings', vals))};
  lsSet(KEY_SAVED, savedSettings);
  startRefresh();   // интервал опроса мог измениться — таймер сразу переводим на новый
  setDraft(null);
  applySettings(savedSettings);
}

/* черновик ведём по всем полям формы; select обрабатываем только на change (input его дублирует) */
$('#view').addEventListener('input', e=>{
  const form = e.target.closest('#sform'); if(!form) return;
  if(e.target.matches('select')) return;
  setDraft(diffSettings(readSettingsForm(form)));
  previewSettings();
});
$('#view').addEventListener('change', e=>{
  const form = e.target.closest('#sform'); if(!form) return;
  if(e.target.matches('select[name="theme"]')) return void persistTheme(e.target.value);
  setDraft(diffSettings(readSettingsForm(form)));
  previewSettings();
});
$('#view').addEventListener('submit', async e=>{
  if(e.target.id !== 'sform') return;
  e.preventDefault();
  try{ await saveSettings(readSettingsForm(e.target)); toast(t('toast.saved')); }
  catch(err){ toast(t('toast.error',{msg:err.message})) }
});

/* ---------- переключатель языка ---------- */
function renderFooterVersion(){
  const mode = $('#mode');
  if(mode) mode.textContent = t('footer.version',{v:PANEL_VERSION});
}

/* статичные подписи (меню, диалоги, кнопки) подставляем из словаря */
function applyStaticI18n(){
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach(el=>{ el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-title]').forEach(el=>{ el.title = t(el.dataset.i18nTitle); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>{ el.placeholder = t(el.dataset.i18nPlaceholder); });
  renderAccount();
  const btn = $('#langBtn'), code = $('#langCode');
  if(code) code.textContent = lang === 'ru' ? 'RU' : 'EN';   // показываем текущий язык
  if(btn) btn.setAttribute('aria-label', t('lang.switch'));
  renderFooterVersion();
}

function setLang(next){
  lang = next === 'en' ? 'en' : 'ru';
  lsSet(KEY_LANG, lang);
  applyStaticI18n();
  show();            // текущую страницу перерисовываем уже на новом языке
}


/* ---------- Диалог аккаунта: пароль, роль, состояние, ключи, удаление ----------
   Раньше на строке висели три кнопки («Пароль», «Отключить», «Удалить») — теперь одна «Изменить»:
   в ней видно всё про учётку и то, что этому человеку разрешено менять. Границы ровно те же,
   что держит бэкенд: владелец не меняется ни для кого, чужие аккаунты — только владельцу,
   пароль — только своему аккаунту. */
let amTarget = null;

async function openAdminEdit(id){
  const list = await call('GET','/api/admins');
  const a = list.find(x=>x.id===id); if(!a) return toast(t('toast.stale'));
  amTarget = a;
  const owner = a.role === 'owner';
  const mine = a.self;
  const manage = canManage() && !owner;
  $('#amtitle').textContent = t('dlg.adminEdit',{name:a.username});
  $('#amlogin').value = a.username;
  $('#amstatus').innerHTML = `<option value="active">${t('dlg.adminEdit.active')}</option><option value="disabled">${t('dlg.adminEdit.disabled')}</option>`;
  $('#amstatus').value = a.status;
  $('#amstatus').disabled = !manage || mine;
  $('#ampw').value = '';
  $('#ampw').disabled = !mine;
  $('#ampwhint').textContent = mine ? t('dlg.adminEdit.passwordHint') : t('dlg.adminEdit.passwordOwnOnly',{name:a.username});
  $('#amdel').hidden = !manage || mine;
  $('#amkeynick').disabled = !(mine || manage);
  $('#amkeyadd').disabled = !(mine || manage);
  const keys = await call('GET', `/api/admins/${a.id}/keys`).catch(()=>[]);
  $('#amkeys').innerHTML = keysHTML(keys, (mine || manage) && (mine || canManage()));
  $('#amdlg').returnValue = '';
  $('#amdlg').showModal();
}

$('#amdlg').addEventListener('submit', async e=>{
  e.preventDefault();
  if(!amTarget) return;
  const a = amTarget, mine = a.self, manage = canManage() && a.role !== 'owner';
  const body = {};
  const pw = $('#ampw').value;
  if(mine && pw) body.password = pw;
  if(manage && !mine && $('#amstatus').value !== a.status) body.status = $('#amstatus').value;
  if(!Object.keys(body).length) return $('#amdlg').close();
  try{
    await call('PATCH','/api/admins/'+a.id, body);
    if(body.status) toast(body.status==='disabled' ? t('toast.adminDisabled') : t('toast.adminEnabled'));
    if(pw && mine) toast(t('toast.passwordChanged'));   // своя сессия осталась: бэкенд её не трогает
    toast(t('toast.adminSaved'));
    $('#amdlg').close();
    show();
  }catch(err){ toast(t('toast.error',{msg:err.message})); }
});

$('#amkeyadd').addEventListener('click', async ()=>{
  if(!amTarget) return;
  try{ await addKey(amTarget.id, $('#amkeynick').value.trim()); $('#amkeynick').value=''; await openAdminEdit(amTarget.id); }
  catch(err){ toast(t('keys.bad',{msg:err.message})); }
});

$('#amdlg').addEventListener('click', async e=>{
  const b = e.target.closest('[data-a="amkeydel"]'); if(!b || !amTarget) return;
  try{ await call('DELETE', `/api/admins/${amTarget.id}/keys/${+b.dataset.id}`); toast(t('keys.removed')); await openAdminEdit(amTarget.id); }
  catch(err){ toast(t('toast.error',{msg:err.message})); }
});

$('#amdel').addEventListener('click', async ()=>{
  if(!amTarget) return;
  if(!confirm(t('confirm.delAdmin'))) return;
  try{ await call('DELETE','/api/admins/'+amTarget.id); toast(t('toast.deleted')); $('#amdlg').close(); show(); }
  catch(err){ toast(t('toast.error',{msg:err.message})); }
});

$('#lform').addEventListener('submit', e=>{ e.preventDefault(); passwordLogin(); });   // preventDefault: диалог закрывает только удачный вход
$('#logkey').addEventListener('click', keyLogin);
$('#logout').addEventListener('click', logout);
$('#langBtn').addEventListener('click', ()=> setLang(lang === 'ru' ? 'en' : 'ru'));

document.querySelectorAll('aside a[data-i]').forEach(a=>a.insertAdjacentHTML('afterbegin', ic(a.dataset.i)));

/* версия панели: бэкенд читает её из pyproject.toml и отдаёт в /api/meta */
async function loadVersion(){
  try{
    const r = await fetch('api/meta', {headers:{'Accept':'application/json'}});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const j = await r.json();
    if(!j || !j.version) throw new Error('нет поля version');
    return String(j.version);
  }catch(err){
    console.warn('не удалось получить версию панели:', err.message);
    return PANEL_VERSION;
  }
}

async function tryMe(){
  /* тестовый режим (?mock=1) — без бэкенда: учётка владельца на месте, чтобы мок-проверки
     видели панель целиком, а не окно входа */
  if(USE_MOCK) return {id:1, username:'admin', role:'owner', expiresAt:Date.now()+DAY, sessions:1};
  if(!tokenGet()) return null;
  try{ return await call('GET','/api/me'); }catch{ tokenSet(''); return null; }   // протухший токен выбрасываем
}

(async()=>{
  PANEL_VERSION = await loadVersion();
  applyStaticI18n();
  const who = await tryMe();                       // есть ли живая сессия с прошлого раза
  if(!who) return askLogin(t('auth.required'));    // без учётки панель не показываем: только окно входа
  meSet(who);
  try{ savedSettings = {...savedSettings, ...(await call('GET','/api/settings'))}; lsSet(KEY_SAVED, savedSettings); }catch(e){}
  applySettings(settingsNow());   // тему и название восстановили до отрисовки — без «мигания»
  syncSettingsUI();               // сразу показываем, что есть несохранённое
  show();
  startRefresh();                 // статус нод обновляется сам, с интервалом из настроек
})();
