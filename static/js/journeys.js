(function(){
  const list = document.getElementById('journey-list');
  const detail = document.getElementById('journey-detail');
  const refresh = document.getElementById('refresh-journeys');
  const lookback = document.getElementById('lookback');
  const proximity = document.getElementById('proximity');
  const limit = document.getElementById('limit');

  async function fetchJourneys(){
    list.innerHTML = 'Loading…';
    detail.innerHTML = 'Select a journey to see details.';
    const q = `?hours=${encodeURIComponent(lookback.value)}&proximity=${encodeURIComponent(proximity.value)}&limit=${encodeURIComponent(limit.value)}`;
    const resp = await fetch('/research/journeys/json/'+q, {credentials:'same-origin'});
    if(!resp.ok){ list.innerHTML = `<p class="text-danger">Failed to fetch journeys: ${resp.status}</p>`; return; }
    const data = await resp.json();
    renderList(data.journeys||[]);
  }

  function renderList(js){
    if(js.length===0){ list.innerHTML = '<p class="text-muted">No journeys found.</p>'; return; }
    list.innerHTML = '';
    js.forEach((j,i)=>{
      const el = document.createElement('div');
      el.className = 'mb-2 d-flex justify-content-between align-items-start';
      el.innerHTML = `<div><strong>${j.session_id.slice(0,10)}…</strong><div class="small text-muted">${j.phases.join(', ')} · ${j.event_count} events</div></div><div><button class="btn btn-sm btn-outline-dark" data-idx="${i}">View</button></div>`;
      el.querySelector('button').addEventListener('click', ()=> showDetail(j));
      list.appendChild(el);
    });
  }

  function showDetail(j){
    detail.innerHTML = `
      <p><strong>Session:</strong> ${j.session_id}</p>
      <p><strong>First seen:</strong> ${j.first_seen} · <strong>Last seen:</strong> ${j.last_seen}</p>
      <p><strong>Duration (s):</strong> ${j.seconds_spent} · <strong>Events:</strong> ${j.event_count}</p>
      <p><strong>Phases:</strong> ${j.phases.join(', ')}</p>
      <h6 class="mt-3">Sample events</h6>
      <div class="list-group mb-2">${j.sample_events.map(e=>`<div class="list-group-item"><div class="d-flex justify-content-between"><div><strong>${e.kind}</strong> · ${e.attack_class||''}</div><div class="small text-muted">${e.ts}</div></div><div class="small text-muted">${e.detail}</div></div>`).join('')}</div>
    `;
  }

  refresh.addEventListener('click', (e)=>{ e.preventDefault(); fetchJourneys(); });
  // initial load
  fetchJourneys();
})();
