const inputStage = document.getElementById('inputStage');
const scanStage = document.getElementById('scanStage');
const resultStage = document.getElementById('resultStage');
const scriptInput = document.getElementById('scriptInput');
const checkBtn = document.getElementById('checkBtn');
const scanLabel = document.getElementById('scanLabel');

const gaugeArc = document.getElementById('gaugeArc');
const scoreNumber = document.getElementById('scoreNumber');
const verdictTitle = document.getElementById('verdictTitle');
const verdictSub = document.getElementById('verdictSub');
const detailsBtn = document.getElementById('detailsBtn');
const detailsPanel = document.getElementById('detailsPanel');
const findingsList = document.getElementById('findingsList');
const resetBtn = document.getElementById('resetBtn');

const CIRCUMFERENCE = 2 * Math.PI * 86; // matches r=86 in the SVG

const scanMessages = [
  'Читаем код…',
  'Ищем подозрительные ссылки…',
  'Проверяем обращения к сервисам…',
  'Считаем итоговую оценку…'
];

function showStage(stage){
  [inputStage, scanStage, resultStage].forEach(s => s.classList.add('hidden'));
  stage.classList.remove('hidden');
}

function verdictFromScore(score){
  if (score >= 80) return { title: 'Похоже, безопасно', color: '#4ADE80',
    sub: 'Явных признаков вредоносного поведения не найдено. Но 100% гарантии не даёт никто — будь внимателен.' };
  if (score >= 40) return { title: 'Осторожно', color: '#FBBF24',
    sub: 'Есть подозрительные признаки. Прежде чем запускать, покажи это взрослому или опытному другу.' };
  return { title: 'Опасно, не запускай', color: '#F87171',
    sub: 'Найдены признаки, характерные для вредоносных скриптов (кража данных, скрытая загрузка кода и т.п.).' };
}

async function analyzeScript(text){
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: text })
  });
  if (!res.ok) throw new Error('analyze_failed');
  return res.json();
}

function renderResult(data){
  const { score, findings } = data;
  const v = verdictFromScore(score);

  scoreNumber.textContent = '0';
  gaugeArc.style.stroke = v.color;
  gaugeArc.style.strokeDashoffset = CIRCUMFERENCE;

  verdictTitle.textContent = v.title;
  verdictTitle.style.color = v.color;
  verdictSub.textContent = v.sub;

  findingsList.innerHTML = '';
  if (!findings || findings.length === 0){
    const li = document.createElement('li');
    li.className = 'finding sev-none';
    li.innerHTML = `<div class="finding-title">Ничего подозрительного не найдено</div>
      <div class="finding-desc">Скрипт не обращается к известным подозрительным адресам и не использует явных приёмов маскировки.</div>`;
    findingsList.appendChild(li);
  } else {
    findings.forEach(f => {
      const li = document.createElement('li');
      li.className = `finding sev-${f.severity}`;
      li.innerHTML = `<div class="finding-title">${f.title}</div>
        <div class="finding-desc">${f.description}</div>`;
      findingsList.appendChild(li);
    });
  }

  detailsPanel.classList.add('hidden');
  detailsBtn.textContent = 'Просмотреть результат';

  showStage(resultStage);

  requestAnimationFrame(() => {
    const offset = CIRCUMFERENCE * (1 - score / 100);
    gaugeArc.style.strokeDashoffset = offset;
    animateNumber(0, score, 900);
  });
}

function animateNumber(from, to, duration){
  const start = performance.now();
  function tick(now){
    const p = Math.min(1, (now - start) / duration);
    const val = Math.round(from + (to - from) * p);
    scoreNumber.textContent = val;
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

checkBtn.addEventListener('click', async () => {
  const text = scriptInput.value.trim();
  if (!text){
    scriptInput.focus();
    return;
  }

  showStage(scanStage);
  let msgIndex = 0;
  scanLabel.textContent = scanMessages[0];
  const msgTimer = setInterval(() => {
    msgIndex = (msgIndex + 1) % scanMessages.length;
    scanLabel.textContent = scanMessages[msgIndex];
  }, 550);

  const minWait = new Promise(r => setTimeout(r, 1300));

  try {
    const [data] = await Promise.all([analyzeScript(text), minWait]);
    clearInterval(msgTimer);
    renderResult(data);
  } catch (err){
    clearInterval(msgTimer);
    renderResult({
      score: 50,
      findings: [{
        severity: 'medium',
        title: 'Не удалось полностью проверить скрипт',
        description: 'Не получилось скачать или разобрать содержимое по ссылке. Будь особенно осторожен и не запускай его сам.'
      }]
    });
  }
});

detailsBtn.addEventListener('click', () => {
  const isHidden = detailsPanel.classList.contains('hidden');
  detailsPanel.classList.toggle('hidden');
  detailsBtn.textContent = isHidden ? 'Скрыть результат' : 'Просмотреть результат';
});

resetBtn.addEventListener('click', () => {
  scriptInput.value = '';
  showStage(inputStage);
});
