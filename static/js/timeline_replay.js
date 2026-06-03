(function(){
  const container = document.getElementById('timeline-events');
  const playBtn = document.getElementById('replay-play');
  const pauseBtn = document.getElementById('replay-pause');
  const speedSel = document.getElementById('replay-speed');
  const ipInput = document.getElementById('ip');
  const sessionInput = document.getElementById('session');
  const attackType = document.getElementById('attack_type');
  const limitSel = document.getElementById('limit');

  let events = [];
  let idx = 0, timer = null;

  function buildQuery(){
    const params = new URLSearchParams();
    if(ipInput && ipInput.value) params.set('ip', ipInput.value);
    if(sessionInput && sessionInput.value) params.set('session', sessionInput.value);
    if(attackType && attackType.value) params.set('attack_type', attackType.value);
    if(limitSel && limitSel.value) params.set('limit', limitSel.value);
    return params.toString()?('?'+params.toString()):'';
  }

  function renderEvents(list){
    container.innerHTML = '';
    list.forEach(ev=>{
      const art = document.createElement('article');
      art.className = 'timeline-item border-start ps-3 pb-4';
      art.dataset.idx = ev.index;
      art.innerHTML = `
        <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
          <span class="badge text-bg-dark">${ev.kind}</span>
          <span class="badge text-bg-secondary">${ev.attack_type||'observed'}</span>
          <strong>${ev.label}</strong>
          <span class="text-muted small ms-auto">${ev.timestamp}</span>
        </div>
        <div class="mb-1"><strong>Detail:</strong> ${escapeHtml(ev.detail||'')}</div>
        <div class="mb-1"><strong>Response:</strong> ${escapeHtml(ev.response||'observed')}</div>
        <div class="mb-1 text-muted small"><strong>IP:</strong> ${ev.ip_address||'unknown'} | <strong>Session:</strong> ${ev.session_id||''}</div>
        ${ev.payload?`<div class="small text-muted text-break"><strong>Payload:</strong> ${escapeHtml(ev.payload)}</div>`:''}
      `;
      container.appendChild(art);
    });
  }

  function escapeHtml(s){ return String(s).replace(/[&<>"']/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c];}); }

  async function fetchEvents(){
    const q = buildQuery();
    const resp = await fetch('/research/timeline/json/'+q, {credentials: 'same-origin'});
    if(!resp.ok){ container.innerHTML = `<p class="text-danger">Failed to fetch timeline: ${resp.status}</p>`; return; }
    const data = await resp.json();
    events = (data.events||[]).map((e,i)=>({...e,index:i}));
    if(events.length===0){ container.innerHTML = '<p class="text-muted mb-0">No timeline events matched the selected filters.</p>' } else { renderEvents(events); }
  }

  function highlight(i){
    const items = container.querySelectorAll('.timeline-item');
    items.forEach((el,j)=> el.style.opacity = j===i?1:0.35);
    if(i>=0 && items[i]) items[i].scrollIntoView({behavior:'smooth', block:'center'});
  }

  function step(){
    if(idx>=events.length){ clearInterval(timer); timer=null; return; }
    highlight(idx);
    idx++;
  }

  playBtn.addEventListener('click', ()=>{
    if(timer) return;
    const sp = parseInt(speedSel.value||1,10);
    timer = setInterval(step, 800 / sp);
  });
  pauseBtn.addEventListener('click', ()=>{ if(timer) clearInterval(timer); timer=null; });

  // refetch when filters change via the form submit; observe submit button
  document.querySelector('form').addEventListener('submit', async (e)=>{ idx=0; if(timer) clearInterval(timer); timer=null; await fetchEvents(); e.preventDefault(); });

  // initial load
  fetchEvents().catch(err=>{ container.innerHTML = `<p class="text-danger">Error loading timeline</p>`; console.error(err); });
})();
