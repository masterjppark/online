/**
 * 율포초 온라인 교무실 — 백엔드 (Google Apps Script)
 * 데이터베이스: 기존 "율포초 온라인 교무실" 스프레드시트 (Settings · MenuLinks · Apps 시트) 그대로 사용
 *
 * 배포: 배포 > 새 배포 > 유형 "웹 앱"
 *   - 다음 사용자 인증 정보로 실행: 나
 *   - 액세스 권한: 모든 사용자   ← GitHub Pages에서 호출하기 위해 필요. 데이터는 교직원 비밀번호 토큰으로 보호됩니다.
 */

var SHEET_ID = '15-KkQXhGqflCT_t-bC1ZRHVMfsngW5AA2fM8zpOCB6Q';
var TOKEN_HOURS = 12;          // 로그인 유지 시간
var STAFF_PW_KEYS = ['generalAdminPassword', 'staffPassword'];   // Settings 시트에서 교직원 비밀번호로 쓸 키(앞에서부터 찾음)
var ADMIN_PW_KEYS = ['adminPassword'];                            // 최고 관리자 비밀번호 키

/* 부서 목록: Depts 시트(부서명 · 묶음 · 아이콘 · 색 · 순서). 시트가 없으면 아래 기본값을 쓰고, 처음 부서를 만들 때 시트를 자동 생성합니다. */
var DEFAULT_DEPTS = [
  ['교무기획부','업무 부서','🗂️'],['교육과정부','업무 부서','📚'],['생활인성부','업무 부서','🤝'],['정보과학부','업무 부서','💻'],['체육안전부','업무 부서','🦺'],
  ['교무실','교실 · 지원','🏫'],['급식실','교실 · 지원','🍱'],['도서실','교실 · 지원','📖'],['보건실','교실 · 지원','🩺'],['수석교사','교실 · 지원','🎓'],['연구학교','교실 · 지원','🔬'],['율포방송국','교실 · 지원','🎬'],['행정실','교실 · 지원','🏛️']
];
var DEPT_COLORS = ['#e8eefc', '#fff1d6', '#ffe4ea', '#dff6f1'];

/* Apps 시트 열 이름 (기존 머리글 그대로) */
var COL = { id: 'ID', dept: '부서명', cat: '업무명', title: '페이지명', url: 'URL 링크', desc: '설명', img: '이미지 링크', show: '표시 여부', owner: '담당자',
            type: '유형', by: '등록자', at: '등록일' };   // 마지막 3개는 없으면 자동으로 추가됩니다

/* ───────── 진입점 ───────── */
function doGet() {
  return json({ ok: true, service: 'yulpo-office', time: new Date().toISOString() });
}

function doPost(e) {
  var req = {};
  try { req = JSON.parse(e.postData.contents || '{}'); } catch (err) { return json({ error: 'BAD_REQUEST' }); }
  try {
    switch (req.action) {
      case 'login':     return json(login_(req));
      case 'bootstrap': auth_(req); return json(bootstrap_());
      case 'inspect':   auth_(req); return json(inspect_(req.url));
      case 'add':       auth_(req); return json(add_(req.item, req.who));
      case 'updateSettings': if (auth_(req) !== 'admin') throw { error: 'FORBIDDEN', message: '최고 관리자만 수정할 수 있어요' };
                        return json(updateSettings_(req.settings));
      case 'saveMenu':  if (auth_(req) !== 'admin') throw { error: 'FORBIDDEN', message: '최고 관리자만 바로 가기를 바꿀 수 있어요' };
                        return json(saveMenu_(req.menu));
      case 'addDept':   if (auth_(req) !== 'admin') throw { error: 'FORBIDDEN', message: '최고 관리자만 부서를 만들 수 있어요' };
                        return json(addDept_(req.dept));
      default:          return json({ error: 'UNKNOWN_ACTION' });
    }
  } catch (err) {
    return json(typeof err === 'object' && err.error ? err : { error: 'SERVER', message: String(err) });
  }
}

/* ───────── 인증 (비밀번호 → 서명 토큰) ───────── */
function login_(req) {
  var s = settings_(), admin = req.admin === true;
  var keys = admin ? ADMIN_PW_KEYS : STAFF_PW_KEYS;
  if (!admin && String(s.useAdminAuth).toUpperCase() === 'FALSE') return issue_('staff');
  var pw = '';
  for (var i = 0; i < keys.length; i++) if (s[keys[i]]) { pw = String(s[keys[i]]); break; }
  // 간단한 무차별 대입 방지: 비밀번호 오류가 1분에 10번을 넘으면 잠시 차단
  var cache = CacheService.getScriptCache(), ck = admin ? 'failA' : 'fail', n = Number(cache.get(ck) || 0);
  if (n > 10) return { error: 'LOCKED', message: '잠시 뒤 다시 시도해 주세요' };
  if (!pw || String(req.password) !== pw) { cache.put(ck, String(n + 1), 60); return { error: 'BAD_PASSWORD', message: '비밀번호가 맞지 않아요' }; }
  return issue_(admin ? 'admin' : 'staff');
}
/* 토큰 = 만료시각.역할.서명  (역할: staff | admin) */
function issue_(role) {
  var exp = Date.now() + TOKEN_HOURS * 3600 * 1000, body = exp + '.' + role;
  return { token: body + '.' + sign_(body), exp: exp, role: role };
}
function auth_(req) {
  var t = String(req.token || '').split('.');
  if (t.length !== 3 || Number(t[0]) < Date.now() || sign_(t[0] + '.' + t[1]) !== t[2]) throw { error: 'AUTH', message: '다시 로그인해 주세요' };
  return t[1];
}
function sign_(s) {
  var p = PropertiesService.getScriptProperties(), key = p.getProperty('SECRET');
  if (!key) { key = Utilities.getUuid() + Utilities.getUuid(); p.setProperty('SECRET', key); }
  return Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(s, key)).replace(/=+$/, '');
}

/* ───────── 데이터 읽기 ───────── */
function bootstrap_() {
  var s = settings_();
  var safe = {};
  ['schoolName', 'mainTitle', 'showNotice', 'noticeText', 'themeColor', 'adminContact'].forEach(function (k) { safe[k] = s[k]; });
  safe.showNotice = String(s.showNotice).toUpperCase() !== 'FALSE';
  return { settings: safe, menu: menu_(), apps: apps_(), depts: depts_() };
}
function settings_() {
  var v = sheet_('Settings').getDataRange().getValues(), o = {};
  v.forEach(function (r) { if (r[0]) o[String(r[0]).trim()] = r[1]; });
  return o;
}
function menu_() {
  var sh = sheet_('MenuLinks'), v = sh.getDataRange().getValues(), h = v.shift();
  var iName = h.indexOf('메뉴명'), iUrl = h.indexOf('URL 링크'), iIc = h.indexOf('아이콘'), iSub = h.indexOf('설명');
  return v.filter(function (r) { return r[iName]; }).map(function (r) {
    return { name: String(r[iName]), url: String(r[iUrl] || ''), e: iIc >= 0 ? String(r[iIc] || '') : '', sub: iSub >= 0 ? String(r[iSub] || '') : '' };
  });
}
function apps_() {
  var t = table_();
  return t.rows.filter(function (r) { return String(t.get(r, 'show')).toUpperCase() !== 'FALSE'; }).map(function (r) {
    var url = String(t.get(r, 'url') || '');
    return {
      id: String(t.get(r, 'id')), dept: String(t.get(r, 'dept') || '기타'), cat: String(t.get(r, 'cat') || '기타'),
      title: String(t.get(r, 'title') || ''), url: url, desc: String(t.get(r, 'desc') || ''),
      owner: String(t.get(r, 'owner') || ''), type: String(t.get(r, 'type') || '') || (url ? detectType_(url) : 'none')
    };
  });
}

/* ───────── 설정 수정 (최고 관리자 · 공지사항) ───────── */
var EDITABLE_SETTINGS = ['noticeText', 'showNotice'];
function updateSettings_(o) {
  o = o || {};
  var sh = sheet_('Settings'), v = sh.getDataRange().getValues();
  EDITABLE_SETTINGS.forEach(function (k) {
    if (!(k in o)) return;
    var val = k === 'showNotice' ? (o[k] ? 'TRUE' : 'FALSE') : String(o[k]).slice(0, 80);
    for (var i = 0; i < v.length; i++) if (String(v[i][0]).trim() === k) { sh.getRange(i + 1, 2).setValue(val); return; }
    sh.appendRow([k, val]);
  });
  return { ok: true };
}

/* ───────── 자주 쓰는 바로 가기 (최고 관리자) ─────────
   MenuLinks 시트를 통째로 다시 씁니다. 아이콘 · 설명 열이 없으면 추가합니다. */
function saveMenu_(list) {
  if (!Array.isArray(list) || list.length > 12) throw { error: 'INVALID', message: '바로 가기는 12개까지 저장할 수 있어요' };
  var rows = list.map(function (m) {
    var name = String(m.name || '').trim().slice(0, 20), url = String(m.url || '').trim();
    if (!name || !/^https?:\/\//.test(url)) throw { error: 'INVALID', message: '이름과 링크를 확인해 주세요' };
    return { name: name, url: url, e: String(m.e || '').slice(0, 4), sub: String(m.sub || '').trim().slice(0, 30) };
  });
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    var sh = sheet_('MenuLinks'), head = sh.getRange(1, 1, 1, Math.max(sh.getLastColumn(), 2)).getValues()[0].map(function (h) { return String(h).trim(); });
    ['메뉴명', 'URL 링크', '아이콘', '설명'].forEach(function (h) { if (head.indexOf(h) < 0) { var c = lastHeaderCol_(head) + 1; head[c] = h; sh.getRange(1, c + 1).setValue(h); } });
    var w = head.length, idx = { name: head.indexOf('메뉴명'), url: head.indexOf('URL 링크'), e: head.indexOf('아이콘'), sub: head.indexOf('설명') };
    if (sh.getLastRow() > 1) sh.getRange(2, 1, sh.getLastRow() - 1, w).clearContent();
    if (rows.length) sh.getRange(2, 1, rows.length, w).setValues(rows.map(function (r) {
      var a = new Array(w).fill(''); for (var k in idx) if (idx[k] >= 0) a[idx[k]] = r[k]; return a;
    }));
    return { ok: true, count: rows.length };
  } finally { lock.releaseLock(); }
}

/* ───────── 부서 ───────── */
function deptSheet_(create) {
  var ss = SpreadsheetApp.openById(SHEET_ID), sh = ss.getSheetByName('Depts');
  if (!sh && create) {
    sh = ss.insertSheet('Depts');
    sh.appendRow(['부서명', '묶음', '아이콘', '색', '순서']);
    DEFAULT_DEPTS.forEach(function (d, i) { sh.appendRow([d[0], d[1], d[2], DEPT_COLORS[i % 4], i + 1]); });
  }
  return sh;
}
function depts_() {
  var sh = deptSheet_(false);
  if (!sh) return DEFAULT_DEPTS.map(function (d, i) { return { name: d[0], group: d[1], icon: d[2], color: DEPT_COLORS[i % 4] }; });
  var v = sh.getDataRange().getValues(); v.shift();
  return v.filter(function (r) { return r[0]; })
    .sort(function (a, b) { return (Number(a[4]) || 999) - (Number(b[4]) || 999); })
    .map(function (r) { return { name: String(r[0]), group: String(r[1] || '기타'), icon: String(r[2] || '📌'), color: String(r[3] || '#eef1f6') }; });
}
function addDept_(d) {
  d = d || {};
  var name = String(d.name || '').trim(), group = String(d.group || '').trim();
  if (!name || name.length > 12 || !group) throw { error: 'INVALID', message: '부서 이름과 묶음을 확인해 주세요' };
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    var sh = deptSheet_(true), norm = function (x) { return String(x).replace(/\s+/g, '').toLowerCase(); };
    var v = sh.getDataRange().getValues(); v.shift();
    var hit = v.filter(function (r) { return norm(r[0]) === norm(name); })[0];
    if (hit) throw { error: 'DUPLICATE_DEPT', message: '‘' + hit[0] + '’ 부서가 이미 있어요' };
    var color = d.color || DEPT_COLORS[v.length % 4], order = v.length + 1;
    sh.appendRow([name, group, d.icon || '📌', color, order]);
    return { dept: { name: name, group: group, icon: d.icon || '📌', color: color } };
  } finally { lock.releaseLock(); }
}

/* ───────── 링크 분석: 유형 · 제목 · 소유자 · 중복 ───────── */
function inspect_(url) {
  url = String(url || '').trim();
  if (!/^https?:\/\//.test(url)) return { error: 'BAD_URL' };
  var key = normKey_(url), dup = findDup_(key);
  var out = { key: key, type: detectType_(url), title: '', owner: '' };
  if (dup) { out.duplicate = dup; return out; }
  var m;
  try {
    if ((m = key.match(/^g:(.+)$/))) {                    // 구글 드라이브 파일: 이름과 소유자
      var f = DriveApp.getFileById(m[1]);
      out.title = f.getName();
      var ow = f.getOwner(); if (ow) out.owner = ow.getName() || '';
    } else if ((m = key.match(/^yt:(.+)$/))) {           // 유튜브: 영상 제목
      var r = UrlFetchApp.fetch('https://www.youtube.com/oembed?format=json&url=' + encodeURIComponent('https://youtu.be/' + m[1]), { muteHttpExceptions: true });
      if (r.getResponseCode() === 200) out.title = JSON.parse(r.getContentText()).title || '';
    } else {                                              // 그 밖의 웹페이지: <title>
      var html = UrlFetchApp.fetch(url, { muteHttpExceptions: true, followRedirects: true }).getContentText().slice(0, 60000);
      var tm = html.match(/<title[^>]*>([^<]{1,120})<\/title>/i);
      if (tm) out.title = tm[1].replace(/\s+/g, ' ').trim();
    }
  } catch (err) { /* 권한이 없거나 비공개면 제목은 비워 둡니다 */ }
  return out;
}
function findDup_(key) {
  if (!key) return null;
  var t = table_();
  for (var i = 0; i < t.rows.length; i++) {
    var r = t.rows[i];
    if (normKey_(String(t.get(r, 'url') || '')) === key)
      return { id: String(t.get(r, 'id')), title: String(t.get(r, 'title')), dept: String(t.get(r, 'dept')), cat: String(t.get(r, 'cat') || '') };
  }
  return null;
}

/* ───────── 등록 (서버에서도 중복을 한 번 더 막습니다) ───────── */
function add_(item, who) {
  item = item || {};
  var title = String(item.title || '').trim(), url = String(item.url || '').trim();
  if (!title || !/^https?:\/\//.test(url)) throw { error: 'INVALID', message: '제목과 링크를 확인해 주세요' };
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    var key = normKey_(url), dup = findDup_(key);
    if (dup) throw { error: 'DUPLICATE', existing: dup };
    var t = table_(true), ids = t.rows.map(function (r) { return parseInt(t.get(r, 'id'), 10) || 0; });
    var id = String(Math.max.apply(null, ids.concat([0])) + 1).padStart(3, '0');
    var row = new Array(t.head.length).fill('');
    var put = function (k, v) { var i = t.idx[k]; if (i >= 0) row[i] = v; };
    put('id', id); put('dept', item.dept || '기타'); put('cat', item.cat || '기타'); put('title', title); put('url', url);
    put('desc', item.desc || ''); put('show', true); put('owner', item.owner || ''); put('type', item.type || detectType_(url));
    put('by', item.owner || ''); put('at', new Date());
    t.sheet.appendRow(row);
    return { item: { id: id, dept: item.dept, cat: item.cat || '기타', title: title, url: url, desc: item.desc || '', owner: item.owner || '', type: item.type || detectType_(url) } };
  } finally { lock.releaseLock(); }
}

/* ───────── 공통 도구 ───────── */
function sheet_(name) { return SpreadsheetApp.openById(SHEET_ID).getSheetByName(name); }
function table_(ensureCols) {
  var sh = sheet_('Apps'), v = sh.getDataRange().getValues(), head = v.shift().map(function (h) { return String(h).trim(); });
  if (ensureCols) ['type', 'by', 'at'].forEach(function (k) {
    if (head.indexOf(COL[k]) < 0) { var c = lastHeaderCol_(head) + 1; sh.getRange(1, c + 1).setValue(COL[k]); head[c] = COL[k]; }
  });
  var idx = {}; for (var k in COL) idx[k] = head.indexOf(COL[k]);
  return { sheet: sh, head: head, idx: idx, rows: v.filter(function (r) { return r[idx.id] !== '' || r[idx.title] !== ''; }),
           get: function (r, k) { return idx[k] >= 0 ? r[idx[k]] : ''; } };
}
function lastHeaderCol_(head) { for (var i = head.length - 1; i >= 0; i--) if (head[i]) return i; return -1; }

/** 같은 문서인데 주소만 다른 경우(/edit, /view, ?usp=sharing …)를 하나로 봅니다. 프론트엔드 normKey와 같은 규칙. */
function normKey_(u) {
  u = String(u || '').trim(); if (!u) return ''; var m;
  if ((m = u.match(/\/macros\/(?:[^/]+\/)?s\/([A-Za-z0-9_-]{20,})/))) return 'gas:' + m[1];
  if ((m = u.match(/\/d\/(?:e\/)?([A-Za-z0-9_-]{15,})/))) return 'g:' + m[1];
  if ((m = u.match(/[?&]id=([A-Za-z0-9_-]{15,})/))) return 'g:' + m[1];
  if ((m = u.match(/(?:youtu\.be\/|[?&]v=|\/shorts\/|\/embed\/)([A-Za-z0-9_-]{11})/))) return 'yt:' + m[1];
  m = u.match(/^https?:\/\/([^/?#]+)([^?#]*)/i);
  return m ? 'u:' + m[1].replace(/^www\./i, '').toLowerCase() + m[2].replace(/\/+$/, '') : 'u:' + u.toLowerCase();
}
function detectType_(u) {
  u = String(u).toLowerCase();
  if (/docs\.google\.com\/spreadsheets/.test(u)) return 'sheet';
  if (/docs\.google\.com\/document/.test(u)) return 'doc';
  if (/docs\.google\.com\/presentation/.test(u)) return 'slide';
  if (/docs\.google\.com\/forms|forms\.gle/.test(u)) return 'form';
  if (/drive\.google\.com/.test(u)) return 'drive';
  if (/script\.google\.com/.test(u)) return 'app';
  if (/youtube\.com|youtu\.be/.test(u)) return 'video';
  if (/notion\.(so|site)/.test(u)) return 'notion';
  if (/chatgpt\.com\/g\/|gemini\.google/.test(u)) return 'ai';
  return 'web';
}
function json(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }

/** (선택) 기존 데이터에 남아 있는 중복 링크를 로그로 확인합니다. 편집기에서 직접 실행하세요. */
function checkDuplicates() {
  var t = table_(), seen = {};
  t.rows.forEach(function (r) {
    var k = normKey_(String(t.get(r, 'url') || '')); if (!k) return;
    (seen[k] = seen[k] || []).push(t.get(r, 'id') + ' ' + t.get(r, 'title'));
  });
  Object.keys(seen).forEach(function (k) { if (seen[k].length > 1) Logger.log('중복: ' + seen[k].join('  =  ')); });
}

/**
 * (한 번만 실행) 업무명(=카테고리) 열이 비어 있는 행에만 기본 카테고리를 채웁니다.
 * 이미 값이 있는 칸은 건드리지 않습니다. 편집기에서 직접 실행하세요.
 */
function fillCategories() {
  var CATS = {
    '3': '위원회·회의',
    '8': '학적·명단',
    '9': '수업·장학',
    '10': '학사 일정',
    '11': '학사 일정',
    '13': '정보기기 유지보수',
    '14': '연수',
    '15': '시설 관리',
    '16': '에듀테크',
    '17': '안전교육 영상',
    '18': '안전교육 영상',
    '19': '안전교육 영상',
    '20': '안전교육 영상',
    '21': '안전교육 영상',
    '22': '안전교육 영상',
    '23': '안전교육 영상',
    '24': '안전교육 영상',
    '25': '안전교육 영상',
    '26': '업무 꿀팁 영상',
    '27': '업무 꿀팁 영상',
    '28': '업무 꿀팁 영상',
    '29': '업무 꿀팁 영상',
    '30': '업무 꿀팁 영상',
    '31': '업무 꿀팁 영상',
    '32': '교사론 시리즈',
    '33': '교사론 시리즈',
    '34': '교사론 시리즈',
    '35': '교사론 시리즈',
    '36': '교사론 시리즈',
    '37': '발표하게 하는 수업',
    '38': '발표하게 하는 수업',
    '39': '발표하게 하는 수업',
    '40': '발표하게 하는 수업',
    '41': '발표하게 하는 수업',
    '42': '발표하게 하는 수업',
    '43': '독서 교육',
    '44': '업무 매뉴얼',
    '45': '연수',
    '46': '시간표·특별실',
    '47': '시간표·특별실',
    '48': '시간표·특별실',
    '49': '시간표·특별실',
    '50': '시간표·특별실',
    '51': '시간표·특별실',
    '52': '시간표·특별실',
    '53': '시간표·특별실',
    '54': '연수',
    '55': '복무',
    '56': '온라인 교무실 안내',
    '57': '업무 매뉴얼',
    '58': 'AI 도우미',
    '59': 'AI 도우미',
    '60': '연구학교 추진',
    '61': '정보기기 유지보수',
    '62': '급식 안내',
    '63': '업무 매뉴얼',
    '64': '주간 안내',
    '65': '수업·장학',
    '66': '보건 장부',
    '67': 'RAS 자료',
    '68': '수업·장학'
  };
  var t = table_(), col = t.idx.cat, filled = [];
  if (col < 0) throw new Error('업무명 열을 찾지 못했어요');
  var all = t.sheet.getDataRange().getValues();
  for (var i = 1; i < all.length; i++) {
    var key = String(parseInt(all[i][t.idx.id], 10));
    if (!CATS[key] || String(all[i][col]).trim() !== '') continue;
    t.sheet.getRange(i + 1, col + 1).setValue(CATS[key]);
    filled.push(all[i][t.idx.id] + '→' + CATS[key]);
  }
  Logger.log('채운 칸 ' + filled.length + '개: ' + filled.join(', '));
}
