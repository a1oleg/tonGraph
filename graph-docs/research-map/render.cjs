/* Regenerate human-readable views from the reviewed hypothesis register.
 * Usage: node graph-docs/research-map/render.cjs
 * Only Node.js built-ins are required. SVG rendering is an optional separate step.
 */
const fs=require('fs');
const path=require('path');
const dir=__dirname;
const d=JSON.parse(fs.readFileSync(path.join(dir,'hypotheses.json'),'utf8'));
const events=new Map(d.events.map(e=>[e.id,e]));
const hypotheses=new Map(d.hypotheses.map(h=>[h.id,h]));
const statuses={negative_within_scope:'Не подтверждено в проверенной области',oracle_rejected:'Ошибочный критерий safety',needs_production_replay:'Нужен production replay',reopened:'Переоткрыта после пересмотра',impact_unproven:'Воздействие не доказано',static_candidate:'Статическая гипотеза',revised_by_guard:'Пересмотрена из-за защит',harness_artifacts_documented:'Артефакты стенда разобраны',new_review_question:'Новый вопрос к коду'};
const ids=new Set();
for(const n of [...d.origins,...d.events,...d.hypotheses]){if(ids.has(n.id))throw Error('Duplicate ID '+n.id);ids.add(n.id);for(const s of n.sources||[])if(!d.sources[s])throw Error('Missing source '+s);}
for(const h of d.hypotheses){if(!statuses[h.status]||!h.next_action||!h.interpretation)throw Error('Incomplete hypothesis '+h.id);for(const id of h.history)if(!events.has(id))throw Error('Missing event '+id);}
for(const h of d.hypotheses)for(const t of h.transitions||[]){if(t.event&&!events.has(t.event))throw Error('Missing transition event');for(const s of t.sources)if(!d.sources[s])throw Error('Missing transition source');}
for(const r of d.relations)if(!hypotheses.has(r.from)||!hypotheses.has(r.to))throw Error('Broken relation');
const esc=s=>s.replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;');
const node=(id,label)=>`  ${id}["${esc(label).replaceAll('\n','<br/>')}"]`;
const theme=`%%{init: {"theme":"base","themeVariables":{"fontFamily":"Arial","fontSize":"16px","primaryColor":"#eef3f8","primaryTextColor":"#182638","primaryBorderColor":"#8195a9","lineColor":"#718096"},"flowchart":{"curve":"basis","htmlLabels":false,"nodeSpacing":25,"rankSpacing":40}}}%%\n`;
const styles=`\n  classDef caution fill:#fff1d8,stroke:#b08029,color:#35270b;\n  classDef rejected fill:#f9e6e5,stroke:#b36b67,color:#502a27;\n  classDef method fill:#e7f3ee,stroke:#668e7b,color:#183e2e;\n`;
const write=(name,lines)=>fs.writeFileSync(path.join(dir,name+'.mmd'),(theme+lines.join('\n')+styles).trimEnd()+'\n');
write('overview',[
'flowchart TB',
node('ROOT','TON Simplex · эволюция исследования\n18 семейств гипотез · 17 эпизодов журнала'),
...d.origins.map(o=>node(o.id,o.title)),
'  ROOT --> O01','  ROOT --> O02','  ROOT --> O03','  ROOT --> O04',
node('CONS','Консенсус · H01–H07\nГолоса, сертификаты, restart, порядок сообщений'),
node('RES','Ресурсы · H08–H14\nMap, очереди, flood, overlay/FEC'),
node('STATIC','Проверка защит · H15–H16\nCall paths, lifetime, caps, quorum'),
'  O01 --> CONS','  O02 --> CONS','  O03 --> RES','  O03 --> STATIC','  O04 --> CONS',
node('WORK','Цикл экспериментов\nМодель → реальный Pool → crash/restart\nSemantic feedback → целевые seeds → replay'),
'  CONS --> WORK','  RES --> WORK','  STATIC --> WORK',
node('REJECT','Пересмотрены / не подтверждены\nNotar+Skip допустим; часть гипотез закрыта защитами'),
node('OPEN','Требуют проверки\nAmnesia, FinalCert, availability, resource impact'),
node('METHOD','Развитие стенда · H17–H18\nДетерминизм, teardown, форматы, санитайзеры'),
'  WORK --> REJECT','  WORK --> OPEN','  WORK --> METHOD',
node('FEEDBACK','Обратная связь в следующий цикл\nИсправить критерии и расширить проверяемую область'),
'  METHOD --> FEEDBACK',
node('NOTE','Статусы — реконструкция по журналу и коду\nПодтверждённые жюри уязвимости из этих данных не установлены'),
'  OPEN --> NOTE','  REJECT --> NOTE','  FEEDBACK --> NOTE',
'  class OPEN caution','  class REJECT rejected','  class METHOD method'
]);
write('consensus-evolution',[
'flowchart TB',
'  subgraph NS["H03 · NotarCert + SkipCert"]',
node('NS1','Предположение: сочетание нарушает safety'),node('NS2','E03–E05 · MockDb + окно + seed\nTrap воспроизводится'),node('NS3','E08 · Trap снимают ради продолжения поиска'),node('NS4','Официальное пояснение TON\nСочетание допустимо → критерий отвергнут'),
'  NS1 --> NS2 --> NS3 --> NS4','  end',
'  subgraph AM["H04 · Amnesia"]',node('AM1','E03 · Потеря записи о голосе'),node('AM2','E05 · Standalone PoC заявлен'),node('AM3','E06 · ResolveState блокирует fuzz-путь'),node('AM4','E09/E13 · Новые seeds и повторное подтверждение в журнале'),node('AM5','Текущий статус: нужен replay\nс реальной durability и допустимым отказом'),
'  AM1 --> AM2 --> AM3 --> AM4 --> AM5','  end',
'  subgraph FC["H05 · Конфликты FinalCert"]',node('FC1','E05/E08 · Certificate traps'),node('FC2','E10 / 5.11 · Сняты как артефакт прямой инжекции'),node('FC3','E13 / 5.18 · Переоткрыты\nзаявлены production CHECK через другие vtypes'),node('FC4','5.19–5.20 · Rebuild и перенос формата seeds'),node('FC5','Текущий статус: переоткрыта\nпроверить допустимость сертификатов и replay'),
'  FC1 --> FC2 --> FC3 --> FC4 --> FC5','  end',
'  NS2 -. "ветвление исследования" .-> AM1','  NS2 -. "разделение классов сертификатов" .-> FC1',
node('AV','H07 / E17 · Переформулировка в availability\nAlarm/restart → abort заявлен; причина требует replay'),
'  NS3 -. "смена заявленного воздействия" .-> AV',
'  class NS4 rejected','  class AM5,FC5,AV caution'
]);
const resources=['flowchart TB',node('R','Гипотезы стоимости обработки и хранения')];
for(const h of d.hypotheses.filter(h=>h.family==='resources')) resources.push(node(h.id,h.id+' · '+h.title+'\n'+statuses[h.status]));
resources.push('  R --> H08','  R --> H09','  R --> H10');
for(const r of d.relations.filter(r=>hypotheses.get(r.from).family==='resources'))resources.push(`  ${r.from} -->|"${r.label}"| ${r.to}`);
resources.push(node('RG','Следующий критерий проверки\nДостижимый трафик + границы lifecycle\nCPU/RAM/байты во времени + влияние на прогресс'));
for(const id of ['H10','H12','H14'])resources.push(`  ${id} --> RG`);
resources.push('  class H08,H09,H10,H11,H12,H13,H14,RG caution');write('resource-evolution',resources);
write('method-evolution',[
'flowchart TB',node('M1','E01/E02 · Модель и TL parser\nБольшое число запусков; ограниченная область'),node('M2','E03 · Реальный Pool + MockDb\nПоявляются restart-состояния'),node('M3','E04 · Semantic/cosine feedback\nНовые сигналы интересных состояний'),node('M4','E05–E07 · Seeds, scheduler, распределение\nДетерминизм и обмен корпусами'),node('M5','E08–E10 · Внутренние события и traps\nПочти каждый вход останавливает поиск'),node('M6','H17 · Разбор стенда\nInvalid BoC, teardown, остаточные события'),node('M7','E11 · UBSan / MSan\nВывод зависит от инструментирования сборки'),node('M8','E12 · Custom mutator + corpus merge'),node('M9','E13 · Дрейф формата входов\nSeeds требуют портирования'),node('M10','H18 · Новый вопрос при составлении карты\nГрамматики мутатор/harness расходятся в коде'),node('M11','E14–E16 · Статический анализ\nПроверки guards и пробелов покрытия'),
'  M1 --> M2 --> M3 --> M4 --> M5 --> M6 --> M8 --> M9 --> M10',
'  M5 --> M7','  M9 --> M11','  M6 -. "продолжить exploration" .-> M3',
'  class M6,M7 method','  class M10 caution'
]);
write('agent-loop',[
'flowchart TB',node('A1','Выбрать H-ID\nclaim + status + next_action'),node('A2','Проверить модель и стенд\nByzantine-вес, durability, grammar, build'),node('A3','Один ограниченный эксперимент\ncommit + binary hash + seed + schedule'),node('A4','Записать наблюдение\nЛог в OneDrive; ссылка и SHA-256 в JSON'),node('A5','Разобрать результат\nДефект? Допустимое поведение? Артефакт?'),node('A6','Добавить событие и переход статуса\nСтарые решения не стирать'),node('A7','Перегенерировать Mermaid / README\nСледующая гипотеза или закрытие'),
'  A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7','  A7 --> A1',
node('AG','FOUND / exit 77 / рост ft\nне переводят гипотезу автоматически в подтверждённый баг'),
'  AG -. "правило классификации" .-> A5','  class AG rejected','  class A4,A6 method'
]);
const link=id=>{const s=d.sources[id];return s.url?`[${id}${s.range?' · '+s.sheet+'!'+s.range:s.path?' · '+s.path+':'+s.line:''}](${s.url})`:`${id}: ${s.text}`;};
let md=`# TON Simplex: как развивались гипотезы\n\nКарта исследования для портфолио и продолжения работы агентом. Источник — журнал Google Sheets (131 строка Sheet1, также Sheet2/Sheet3) и код на commit \`4ee8eb0e\`. Чтение выполнено 29 сентября 2026; эксперименты заново не запускались.\n\n**18 семейств гипотез и 17 сгруппированных эпизодов — редакционная структура карты, не число независимых багов или запусков.** Две недели и три машины — контекст автора; полный архив кампании не подтверждён. Персональные вердикты не привязаны к отчётам, поэтому слова «принят» и «ПОДТВЕРЖДЁН» из журнала не трактуются как подтверждение жюри.\n\n![Обзор исследования](overview.svg)\n\n[Исходник Mermaid](overview.mmd) · [Реестр для агента](hypotheses.json)\n\n## Что показывает карта\n\nГипотезы рождались из аналогий BFT, предполагаемых инвариантов, пробелов покрытия и статического анализа. Плато вело к усложнению стенда; новые срабатывания — к исправлению стенда и пересмотру критериев. Связи «развилось из» являются аналитической реконструкцией, а не доказанным порядком мыслей автора.\n\nГлавное различие: **исследуемое свойство → наблюдение → интерпретация → следующий эксперимент**. Воспроизводимость искусственного trap, безопасность модели и реальная уязвимость — разные утверждения.\n\n## Эволюция консенсусных гипотез\n\n![Развитие консенсусных гипотез](consensus-evolution.svg)\n\nСамый выразительный пересмотр: H05 была снята в 5.11 как артефакт, затем переоткрыта в 5.18. H03 имеет другой исход: допустимость Notar+Skip прямо указана в официальных пояснениях. Это не индивидуальный вердикт отчёту: ${link('S-verdicts')}.\n\n## Разветвление ресурсных гипотез\n\n![Развитие ресурсных гипотез](resource-evolution.svg)\n\nПорог размера структуры — средство обнаружения интересного состояния. Чтобы утверждать DoS, нужен измеренный эффект в допустимой модели нагрузки.\n\n## Развитие метода\n\n![Развитие стенда](method-evolution.svg)\n\nH18 добавлена при этой реконструкции: связанный в CMake мутатор описывает старую грамматику входа, тогда как harness расширен. Это вопрос для проверки совместимости, не новая подтверждённая уязвимость.\n\n## Реестр гипотез\n\n| ID | Гипотеза | Текущая оценка | Эпизоды |\n|---|---|---|---|\n`;
for(const h of d.hypotheses)md+=`| [${h.id}](#${h.id.toLowerCase()}) | ${h.title} | ${statuses[h.status]} | ${h.history.join(' → ')||'Новый обзор кода'} |\n`;
md+='\n## Журнал развития метода\n\nЧисла ниже — утверждения журнала, не результаты повторного запуска. Coverage разных сборок и наборов feedback нельзя напрямую складывать или сравнивать. Эпизоды сгруппированы по смыслу; E11 объединяет две несмежные фазы.\n\n';
for(const e of d.events)md+=`### ${e.id} · ${e.phase} · ${e.title}\n\n**Повод:** ${e.trigger}. **Действие:** ${e.action}.\n\n**Записанное наблюдение:** ${e.observation}. **Ограничение:** ${e.limitation}.\n\n${e.sources.map(link).join(' · ')}\n\n`;
md+='## Карточки гипотез\n\n';
for(const h of d.hypotheses)md+=`<a id="${h.id.toLowerCase()}"></a>\n\n### ${h.id} · ${h.title}\n\n- **Откуда:** ${h.origin}.\n- **Проверяемое утверждение:** ${h.claim}.\n- **Развитие:** ${h.history.map(id=>id+' / '+events.get(id).phase).join(' → ')||'Новое наблюдение при реконструкции'}.\n- **Оценка сейчас:** ${statuses[h.status]}. ${h.interpretation}\n- **Следующее действие:** ${h.next_action}\n\n${h.sources.map(link).join(' · ')}\n\n`;
md+=`## Использование в agentic loop\n\n![Предлагаемый цикл агента](agent-loop.svg)\n\nЭто **предлагаемый порядок дальнейшей работы**, а не утверждение, что исторические эксперименты выполнялись автономным агентом.\n\n1. Единственный редактируемый реестр — \`hypotheses.json\`; ID гипотез сохраняются.\n2. К каждому новому наблюдению добавляются источник, уровень доказательности и версия кода. Результаты экспериментов остаются в OneDrive; в Git — ссылки и хеши.\n3. Историю решений дополнять, а не переписывать. Переоткрытие требует нового свидетельства.\n4. Не присваивать статус подтверждённого дефекта на основании текста журнала, номера trap или роста покрытия.\n5. Выполнить \`node graph-docs/research-map/render.cjs\`: проверка ссылочной целостности и обновление Mermaid/README.\n6. Для обновления SVG использовать Mermaid CLI 11.12.0: \`mmdc -i overview.mmd -o overview.svg -b white\` и аналогично для остальных четырёх диаграмм. Для уже экспортированных SVG зависимости не требуются.\n\n## Формулировка для резюме\n\n«Разработал и итеративно расширял стенд фаззинга TON Simplex: модель протокола, реальный actor runtime, crash/restart-сценарии, семантическую обратную связь и структурные мутации. Организовал распределённые прогоны и анализ корпусов, исследовал причины ложных срабатываний, применял санитайзеры и статический анализ. Систематизировал происхождение гипотез, результаты проверок и причины пересмотра в воспроизводимом реестре».\n\nЭта формулировка описывает выполненную инженерную работу и не заявляет принятые уязвимости.\n`;
md=md.replace('## Что показывает карта','## Матрица: гипотезы × этапы\n\n[Открыть табличную диаграмму](MATRIX.md) · [Все колонки, SVG](matrix.svg) · [Автономная интерактивная версия](matrix.html)\n\nКолонки — гипотезы; ряды — этапы. Общий этап записан один раз со стрелками из связанных колонок.\n\n## Что показывает карта');
fs.writeFileSync(path.join(dir,'README.md'),md);
console.log(`Validated ${ids.size} IDs; wrote five Mermaid views and README`);
