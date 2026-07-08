// Vercel Serverless Function: POST /api/analyze
// Body: { input: string }  -> either raw Lua code, a loadstring(...) wrapper, or a plain URL.
// Response: { score: number 0-100, findings: [{ severity, title, description }] }
//
// IMPORTANT: this function never executes the script. It only downloads the
// text (if a URL is given) and pattern-matches it. Raw code is never sent
// back to the browser — only human-readable descriptions of what was found.

const URL_REGEX = /https?:\/\/[^\s"')]+/i;

const RULES = [
  {
    id: 'discord-webhook',
    pattern: /discord(?:app)?\.com\/api\/webhooks/i,
    severity: 'high',
    points: 45,
    title: 'Отправляет данные в Discord',
    description: 'Скрипт содержит адрес Discord-webhook. Так обычно воруют данные аккаунта или переписку — они незаметно уходят кому-то в Discord.'
  },
  {
    id: 'webhook-site',
    pattern: /webhook\.site|requestbin|ip-api\.com|iplogger|grabify/i,
    severity: 'high',
    points: 40,
    title: 'Обращается к сервису слежки/логирования',
    description: 'Найден адрес сервиса, который часто используют, чтобы узнать твой IP-адрес или другие данные о тебе.'
  },
  {
    id: 'nested-loadstring',
    pattern: /loadstring\s*\(\s*game\s*:\s*HttpGet/i,
    severity: 'medium',
    points: 15,
    title: 'Загружает код с внешнего адреса',
    description: 'Скрипт скачивает и сразу выполняет ещё один кусок кода с другого сайта. Ты не видишь, что именно там — это может быть что угодно, включая вредоносный код.'
  },
  {
    id: 'writefile',
    pattern: /\b(writefile|appendfile|delfile|delfolder|makefolder)\s*\(/i,
    severity: 'high',
    points: 35,
    title: 'Пытается работать с файлами на компьютере',
    description: 'Скрипт использует функции для записи или удаления файлов. Обычным игровым скриптам это не нужно — так делают вредоносные программы.'
  },
  {
    id: 'exploit-env',
    pattern: /\b(getgenv|getrenv|getreg|hookfunction|hookmetamethod|getconnections|checkcaller)\s*\(/i,
    severity: 'medium',
    points: 20,
    title: 'Использует функции обхода защиты',
    description: 'Найдены функции, которые обычно используют читы-эксплойты, чтобы прятать своё поведение от игры и от других скриптов.'
  },
  {
    id: 'player-exfil',
    pattern: /(LocalPlayer|UserId|Players\.LocalPlayer)[\s\S]{0,120}(HttpGet|HttpPost|request\s*\()/i,
    severity: 'high',
    points: 30,
    title: 'Может отправлять данные о твоём аккаунте',
    description: 'Скрипт читает данные об игроке (например, ID аккаунта) рядом с сетевым запросом. Это похоже на попытку отправить твои данные куда-то ещё.'
  },
  {
    id: 'saveinstance',
    pattern: /\bsaveinstance\s*\(/i,
    severity: 'medium',
    points: 15,
    title: 'Пытается скопировать игру целиком',
    description: 'Функция saveinstance используется для копирования содержимого игры — обычно ради кражи чужой работы, к безопасности твоего аккаунта это не относится, но это неэтичное использование.'
  },
  {
    id: 'obfuscated',
    pattern: /(string\.char\s*\([^)]{60,}\)|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){15,})/i,
    severity: 'medium',
    points: 15,
    title: 'Код сильно замаскирован (обфусцирован)',
    description: 'Большая часть кода закодирована так, чтобы её было трудно прочитать. Само по себе это не всегда плохо, но часто используется, чтобы скрыть вредоносные действия.'
  },
  {
    id: 'suspicious-keywords',
    pattern: /\b(stealer|grabber|logger|backdoor|inject(?:ion)?|trojan)\b/i,
    severity: 'high',
    points: 30,
    title: 'В коде есть слова, характерные для вредоносных программ',
    description: 'Встречаются термины, которые авторы вредоносных скриптов часто используют для названий своих функций.'
  }
];

function analyzeCode(code){
  const findings = [];
  let score = 100;

  for (const rule of RULES){
    if (rule.pattern.test(code)){
      findings.push({
        severity: rule.severity,
        title: rule.title,
        description: rule.description
      });
      score -= rule.points;
    }
  }

  score = Math.max(0, Math.min(100, score));
  return { score, findings };
}

async function fetchRemote(url){
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return null;
    const text = await res.text();
    return text.slice(0, 200000); // cap size
  } catch (e){
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST'){
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string'){
    try { body = JSON.parse(body); } catch (e){ body = {}; }
  }
  const input = (body && body.input ? String(body.input) : '').trim();

  if (!input){
    res.status(400).json({ error: 'empty_input' });
    return;
  }

  let codeToAnalyze = input;

  const urlMatch = input.match(URL_REGEX);
  if (urlMatch){
    const remote = await fetchRemote(urlMatch[0]);
    if (remote){
      codeToAnalyze += '\n' + remote;
    } else {
      // Could not fetch — flag that explicitly instead of silently scoring blind.
      res.status(200).json({
        score: 45,
        findings: [{
          severity: 'medium',
          title: 'Не удалось скачать содержимое ссылки',
          description: 'Мы не смогли получить сам код по ссылке (сайт мог заблокировать запрос или ссылка недоступна). Раз мы не можем его прочитать — считай это поводом для осторожности.'
        }]
      });
      return;
    }
  }

  const result = analyzeCode(codeToAnalyze);
  res.status(200).json(result);
};
