/* Node built-ins only. Regenerate the matrix SVGs and standalone interactive HTML. */
const fs=require('fs'),path=require('path');
const dir=__dirname;
const data=JSON.parse(fs.readFileSync(path.join(dir,'hypotheses.json'),'utf8'));
function matrixParts(data, family='all') {
 const cw=180,lw=220,rh=176,hh=122;
 const hs=data.hypotheses.filter(h=>family==='all'||h.family===family);
 const width=cw*hs.length;
 const x=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
 const wrap=(s,max)=>{const lines=[];let line='';for(const word of s.split(/\s+/)){if(line&&line.length+word.length+1>max){lines.push(line);line=word;}else line+=(line?' ':'')+word;}if(line)lines.push(line);return lines;};
 const text=(s,cx,y,max=25,size=14,color='#26384a')=>`<text x="${cx}" y="${y}" text-anchor="middle" fill="${color}" font-family="Arial,sans-serif" font-size="${size}">${wrap(s,max).map((l,i)=>`<tspan x="${cx}" dy="${i?size+4:0}">${x(l)}</tspan>`).join('')}</text>`;
 const palette={consensus:'#e8f0fb',resources:'#fff2dd',static:'#eef0f3',method:'#e4f3ed'};
 const grid=h=>hs.map((_,i)=>`<line x1="${i*cw}" y1="0" x2="${i*cw}" y2="${h}" stroke="#e3e9ef"/><line x1="${i*cw+cw/2}" y1="0" x2="${i*cw+cw/2}" y2="${h}" stroke="#e8edf3" stroke-dasharray="3 5"/>`).join('');
 const header=hs.map((h,i)=>`<g data-hypothesis="${h.id}" role="button" tabindex="0" aria-label="${x(h.id+' '+h.title)}"><rect x="${i*cw+5}" y="6" width="${cw-10}" height="108" rx="7" fill="${palette[h.family]}" stroke="#b7c4d1"/>${text(h.id,i*cw+cw/2,30,26,15)}${text(h.title,i*cw+cw/2,54,22,14)}</g>`).join('');
 const rows=[];
 for(const e of data.events){
   const participating=hs.map((h,i)=>h.history.includes(e.id)?i:-1).filter(i=>i>=0);
   if(!participating.length&&family!=='all')continue;
   const mid=participating.length?participating.reduce((sum,i)=>sum+i*cw+cw/2,0)/participating.length:width/2;
   const boxW=Math.min(550,width-30),boxX=Math.max(15,Math.min(width-boxW-15,mid-boxW/2));
   const center=boxX+boxW/2;
   let svg=grid(rh);
   const min=Math.min(center,...participating.map(i=>i*cw+cw/2));
   const max=Math.max(center,...participating.map(i=>i*cw+cw/2));
   svg+=`<line x1="${min}" y1="35" x2="${max}" y2="35" stroke="#72869b" stroke-width="1.5"/>`;
   for(const i of participating){const cx=i*cw+cw/2;svg+=`<circle cx="${cx}" cy="13" r="4" fill="#436d98"/><path d="M${cx},17 V35" stroke="#72869b" fill="none" marker-end="url(#arr)"/>`;}
   if(participating.length)svg+=`<path d="M${center},35 V53" stroke="#72869b" fill="none" marker-end="url(#arr)"/>`;
   svg+=`<g data-event="${e.id}" role="button" tabindex="0" aria-label="${x(e.title)}"><rect x="${boxX}" y="54" width="${boxW}" height="83" rx="7" fill="#f5f8fc" stroke="#91a7be"/>${text(e.title,center,77,Math.floor(boxW/8.5),15)}${text(e.action,center,101,Math.floor(boxW/7.1),12)}</g>`;
   // A single common stage, with paths returning to exactly its participating columns.
   if(participating.length)svg+=`<path d="M${center},137 V151 H${min} M${center},151 H${max}" fill="none" stroke="#9dadbd"/>`;
   else svg+=text('Самостоятельная проверка; в реестре не привязана к H-ID',center,161,80,12);
   for(const i of participating){const cx=i*cw+cw/2;svg+=`<path d="M${cx},151 V170" fill="none" stroke="#9dadbd" marker-end="url(#arr)"/>`;}
   rows.push({id:e.id,phase:e.phase,title:e.title,svg,participants:participating.map(i=>hs[i].id)});
 }
 const statusLabels={negative_within_scope:'Не подтверждено в области проверки',oracle_rejected:'Критерий отвергнут',needs_production_replay:'Нужен production replay',reopened:'Переоткрыта',impact_unproven:'Воздействие не доказано',static_candidate:'Статическая гипотеза',revised_by_guard:'Пересмотрена: есть защита',harness_artifacts_documented:'Разобраны артефакты стенда',new_review_question:'Новый вопрос обзора'};
 const status=grid(hh)+hs.map((h,i)=>`<g data-hypothesis="${h.id}" role="button" tabindex="0"><rect x="${i*cw+6}" y="10" width="${cw-12}" height="100" rx="6" fill="${h.status==='oracle_rejected'?'#fbe9e7':'#f7f8fa'}" stroke="#bec9d4"/>${text(h.id,i*cw+cw/2,35,22,14)}${text(statusLabels[h.status],i*cw+cw/2,59,22,13)}</g>`).join('');
 const defs='<defs><marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#72869b"/></marker></defs>';
 return {hs,width,lw,rh,hh,header,rows,status,defs,text,x};
}
function svg(data,family){
 const p=matrixParts(data,family),w=p.width+p.lw,h=p.hh+p.rows.length*p.rh+p.hh+80;
 let body=`<rect width="${w}" height="${h}" fill="white"/>${p.text('Гипотезы →',p.lw/2,37,25,18)}${p.text('Этапы ↓',p.lw/2,69,25,16)}<g transform="translate(${p.lw},0)">${p.header}</g>`;
 p.rows.forEach((r,i)=>{const y=p.hh+i*p.rh;body+=`<g transform="translate(0,${y})"><rect width="${w}" height="${p.rh}" fill="${i%2?'#fbfcfe':'#fff'}"/><line x1="0" y1="0" x2="${w}" y2="0" stroke="#dce4ec"/>${p.text(r.id,p.lw/2,37,25,17)}${p.text(r.phase,p.lw/2,63,24,14)}${p.text(r.participants.length+' связей',p.lw/2,90,24,13)}<g transform="translate(${p.lw},0)">${r.svg}</g></g>`;});
 const sy=p.hh+p.rows.length*p.rh;body+=`<g transform="translate(0,${sy})">${p.text('Оценка сейчас',p.lw/2,54,25,16)}<g transform="translate(${p.lw},0)">${p.status}</g></g>`;
 body+=p.text('Точка — участие гипотезы. Общий блок записан один раз. Пустая колонка в ряду не означает опровержение.',w/2,h-35,150,14);
 return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="Матрица гипотез и этапов исследования">${p.defs}${body}</svg>`;
}
fs.writeFileSync(path.join(dir,'matrix.svg'),svg(data,'all'));
fs.writeFileSync(path.join(dir,'matrix-consensus.svg'),svg(data,'consensus'));
const json=JSON.stringify(data).replaceAll('<','\\u003c');
const html=`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TON Simplex · гипотезы × этапы</title>
<style>
*{box-sizing:border-box}body{margin:0;font:15px/1.45 Arial,sans-serif;color:#26384a;background:#fff}header{padding:22px 28px 14px}h1{font-size:25px;margin:0 0 6px}p{margin:6px 0;color:#526577}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:15px 0 8px}button{font:inherit;border:1px solid #bac8d5;background:#fff;border-radius:6px;padding:8px 13px;color:#26384a;cursor:pointer}button[aria-pressed=true]{background:#243d57;color:#fff;border-color:#243d57}button:focus-visible,[tabindex]:focus-visible{outline:3px solid #287ac7;outline-offset:2px}.frame{margin:0 28px 24px;border:1px solid #dce4ec;max-height:72vh;overflow:auto;position:relative}.row{display:grid;grid-template-columns:220px auto;width:max-content}.label{position:sticky;left:0;background:#f4f7fa;border-bottom:1px solid #dce4ec;border-right:1px solid #dce4ec;padding:22px 18px;width:220px;z-index:2}.label b{font-size:17px;display:block}.label span{display:block;margin-top:5px;color:#526577}.label small{display:block;margin-top:8px}.head{position:sticky;top:0;z-index:4;background:#fff}.head .label{z-index:5}.row svg{display:block;background:#fff;border-bottom:1px solid #dce4ec}.row:nth-child(2n) svg{background:#fbfcfe}g[role=button]{cursor:pointer}g[role=button]:hover rect{stroke:#27699d;stroke-width:2}.detail{margin:0 28px 30px;max-width:1100px;min-height:120px}.detail h2{font-size:19px;margin-bottom:10px}.detail p{color:#26384a}.detail a{color:#1766a5}.badge{font-size:13px;color:#526577}#hint{font-size:13px}@media(max-width:600px){header{padding:16px}.frame{margin:0 12px 20px}.detail{margin:0 16px}.label{width:155px;padding:12px}.row{grid-template-columns:155px auto}h1{font-size:21px}}
</style><header><h1>Гипотезы × этапы исследования</h1><p>Колонки сохраняют гипотезы. Общий этап записан один раз: пути сходятся в блок и возвращаются в свои колонки.</p><nav class="toolbar" aria-label="Группа гипотез"><button data-family="consensus" aria-pressed="true">Консенсус · 7</button><button data-family="resources" aria-pressed="false">Ресурсы · 7</button><button data-family="static" aria-pressed="false">Проверка защит · 2</button><button data-family="method" aria-pressed="false">Метод · 2</button><button data-family="all" aria-pressed="false">Все · 18</button></nav><p id="hint">Точка — связь гипотезы с этапом: проверка или отмеченное ограничение. Нажмите заголовок колонки или общий блок для деталей и источников. Пусто — нет связи в реестре, а не отрицательный результат.</p></header><main><div class="frame" tabindex="0" aria-label="Прокручиваемая матрица"><div id="matrix"></div></div><section class="detail" id="detail" aria-live="polite"><h2>Чтение матрицы</h2><p>Ряды — сгруппированные эпизоды журнала, не точная временная шкала: E11 объединяет 5.8 и 5.14. Общность этапов восстановлена по реестру; участие не означает одинаковый результат.</p><p>H18 — новый вопрос при обзоре кода; исторических этапов у него нет. Текущие статусы находятся в последнем ряду.</p></section></main>
<script>const data=${json};const matrixParts=${matrixParts.toString()};
const target=document.getElementById('matrix'),detail=document.getElementById('detail');
const escape=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
function sources(ids){return ids.map(id=>{const s=data.sources[id];return s.url?'<a target="_blank" rel="noopener" href="'+escape(s.url)+'">'+escape(id+(s.range?' · '+s.sheet+'!'+s.range:''))+'</a>':escape(id);}).join(' · ');}
function show(type,id){if(type==='event'){const e=data.events.find(e=>e.id===id);const hs=data.hypotheses.filter(h=>h.history.includes(id));detail.innerHTML='<h2>'+escape(e.id+' · '+e.phase+' · '+e.title)+'</h2><p><b>Участвуют:</b> '+hs.map(h=>escape(h.id+' '+h.title)).join('; ')+'</p><p><b>Повод:</b> '+escape(e.trigger)+'</p><p><b>Действие:</b> '+escape(e.action)+'</p><p><b>Записано в журнале:</b> '+escape(e.observation)+'</p><p><b>Ограничение:</b> '+escape(e.limitation)+'</p><p>'+sources(e.sources)+'</p>';}else{const h=data.hypotheses.find(h=>h.id===id);detail.innerHTML='<h2>'+escape(h.id+' · '+h.title)+'</h2><p><b>Гипотеза:</b> '+escape(h.claim)+'</p><p><b>Происхождение:</b> '+escape(h.origin)+'</p><p><b>Оценка:</b> '+escape(h.interpretation)+'</p><p><b>Дальше:</b> '+escape(h.next_action)+'</p><p>'+sources(h.sources)+'</p>';}}
function render(family){const p=matrixParts(data,family);const img=(inner,height)=>'<svg xmlns="http://www.w3.org/2000/svg" width="'+p.width+'" height="'+height+'" viewBox="0 0 '+p.width+' '+height+'">'+p.defs+inner+'</svg>';target.innerHTML='<div class="row head"><div class="label"><b>Этапы ↓</b><span>Гипотезы →</span><small>'+p.hs.length+' колонок</small></div>'+img(p.header,p.hh)+'</div>'+p.rows.map(r=>'<div class="row"><div class="label"><b>'+r.id+'</b><span>'+escape(r.phase)+'</span></div>'+img(r.svg,p.rh)+'</div>').join('')+'<div class="row"><div class="label"><b>Оценка сейчас</b><small>Не вердикт жюри</small></div>'+img(p.status,p.hh)+'</div>';document.querySelectorAll('[data-family]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.family===family)));target.querySelectorAll('[data-hypothesis],[data-event]').forEach(g=>{const action=()=>show(g.dataset.event?'event':'hypothesis',g.dataset.event||g.dataset.hypothesis);g.addEventListener('click',action);g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();action();}});});document.querySelector('.frame').scrollTo(0,0);}
document.querySelectorAll('[data-family]').forEach(b=>b.addEventListener('click',()=>render(b.dataset.family)));render('consensus');
</script></html>`;
fs.writeFileSync(path.join(dir,'matrix.html'),html);
console.log('Generated matrix.html, matrix.svg and matrix-consensus.svg');
