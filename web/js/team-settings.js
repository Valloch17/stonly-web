if (typeof window.requireAccount === 'function') {
  window.requireAccount();
}

const BASE = (window.BASE || window.DEFAULT_BACKEND || '').replace(/\/+$/, '');
const table = document.getElementById('teamTable');
const statusNode = document.getElementById('teamSettingsStatus');
const newBtn = document.getElementById('teamNewBtn');

let teams = [];

function setStatus(msg, tone) {
  if (!statusNode) return;
  statusNode.textContent = msg || '';
  statusNode.classList.remove('text-slate-500', 'text-red-600', 'text-green-600');
  if (tone === 'error') statusNode.classList.add('text-red-600');
  else if (tone === 'success') statusNode.classList.add('text-green-600');
  else statusNode.classList.add('text-slate-500');
}

function renderTeams(list) {
  teams = Array.isArray(list) ? list : [];
  if (!table) return;
  table.innerHTML = '';
  if (!teams.length) {
    table.innerHTML = '<tr><td colspan="5" class="px-3 py-3 text-center text-slate-500 italic">Team list is empty, please create one.</td></tr>';
    return;
  }
  teams.forEach((team) => {
    const tr = document.createElement('tr');
    const created = team.createdAt ? new Date(team.createdAt).toLocaleString() : '-';
    tr.innerHTML = `
      <td class="px-3 py-2 border-b">${team.name || '-'}</td>
      <td class="px-3 py-2 border-b font-mono text-xs">${team.teamId}</td>
      <td class="px-3 py-2 border-b">${team.rootFolder ?? '-'}</td>
      <td class="px-3 py-2 border-b text-xs text-slate-500">${created}</td>
      <td class="px-3 py-2 border-b">
        <button class="team-edit px-2 py-1 rounded border text-xs" data-id="${team.id}">Edit</button>
        <button class="team-delete ml-2 px-2 py-1 rounded border text-xs text-red-600" data-id="${team.id}">Delete</button>
      </td>
    `;
    table.appendChild(tr);
  });
}

async function loadTeams() {
  setStatus('Loading teams...');
  try {
    const res = await fetch(BASE + '/api/teams', { credentials: 'include' });
    if (!res.ok) throw new Error('Failed to load teams');
    const data = await res.json();
    renderTeams(data?.teams || []);
    setStatus('');
  } catch (e) {
    setStatus(e?.message || 'Failed to load teams', 'error');
  }
}

async function deleteTeam(teamId) {
  try {
    const res = await fetch(BASE + `/api/teams/${teamId}`, { method: 'DELETE', credentials: 'include' });
    if (!res.ok) throw new Error('Failed to delete team');
    setStatus('Team deleted.', 'success');
    await loadTeams();
    if (typeof window.__reloadTeamSelect === 'function') {
      window.__reloadTeamSelect();
    }
  } catch (e) {
    setStatus(e?.message || 'Failed to delete team', 'error');
  }
}

function handleTableClick(event) {
  const target = event.target;
  if (!target) return;
  const id = target.getAttribute('data-id');
  if (!id) return;
  const team = teams.find((t) => String(t.id) === String(id));
  if (!team) return;

  if (target.classList.contains('team-edit')) {
    if (typeof window.openTeamModal === 'function') {
      window.openTeamModal({
        mode: 'edit',
        team,
        onSaved: (saved) => {
          loadTeams();
          const nextId = saved?.teamId || team.teamId;
          if (typeof window.__reloadTeamSelect === 'function') {
            window.__reloadTeamSelect(String(nextId));
          }
        },
      });
    }
  }
  if (target.classList.contains('team-delete')) {
    if (confirm('Delete this team? This cannot be undone.')) {
      deleteTeam(team.id);
    }
  }
}

newBtn?.addEventListener('click', () => {
  if (typeof window.openTeamModal === 'function') {
    window.openTeamModal({
      mode: 'create',
      onSaved: () => {
        loadTeams();
      },
    });
  }
});

(table || document).addEventListener('click', handleTableClick);

loadTeams();
