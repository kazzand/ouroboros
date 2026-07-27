// Activity dashboard subtab (P4): observability and direct mechanical controls.
// Remote placement is presentation-only here: task lifecycle remains queue-owned,
// while SSH retry uses the existing owner connection test and never replays work.

import { apiClient, apiFetch } from './api_client.js';
import {
    mergeRemoteTaskState,
    normalizeRemoteTaskState,
    remotePlacementFromTask,
    remoteDetailText,
    remoteStateDetails,
    remoteStateLabel,
    remoteStateSummary,
    remoteTaskActions,
} from './remote_task_state.js';

function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
}

async function getJson(url) {
    try {
        const resp = await apiFetch(url, { cache: 'no-store' });
        if (resp && typeof resp.json === 'function') {
            if (resp.ok === false) return null;
            return await resp.json();
        }
        return resp;
    } catch {
        return null;
    }
}

function isSkillManaged(schedule) {
    return Boolean(schedule && (
        String(schedule.source || '') === 'skill_manifest' || String(schedule.skill || '')
    ));
}

function taskIdOf(task = {}) {
    return String(task.task_id || task.id || '');
}

function taskLabel(task = {}, fallback = 'task') {
    return String(
        task.title || task.description || task.objective || task.text || taskIdOf(task) || fallback,
    );
}

function renderRemoteDetails(state) {
    const details = remoteStateDetails(state);
    if (!details.length) return '';
    return `<details class="activity-remote-details">
        <summary>Diagnostics &amp; logs</summary>
        ${details.map((item) => {
            const href = String(
                item.value?.download_url || item.value?.url || item.value?.full_ref || '',
            );
            const link = /^\/api\/[A-Za-z0-9_?&=./%-]+$/.test(href)
                ? `<a href="${esc(href)}" target="_blank" rel="noopener">Open full log</a>`
                : '';
            return `<div class="activity-remote-evidence">
                <div><strong>${esc(item.label)}</strong>${link}</div>
                <pre>${esc(remoteDetailText(item.value))}</pre>
            </div>`;
        }).join('')}
    </details>`;
}

function renderRemoteStatus(state) {
    if (!state) return '';
    const tone = ['degraded', 'disconnected'].includes(state.status) ? 'warn' : state.status;
    return `<span class="activity-connection-state" data-state="${esc(tone)}">
        ${esc(remoteStateLabel(state.status))}
    </span>`;
}

function renderRemoteActions(state) {
    const actions = remoteTaskActions(state);
    return [
        actions.canReconnect
            ? `<button type="button" class="btn btn-xs btn-default" data-act="connection-reconnect" data-id="${esc(state.connectionId)}" data-task-id="${esc(state.taskId)}">Reconnect</button>`
            : '',
        actions.canCancel
            ? `<button type="button" class="btn btn-xs btn-danger" data-act="task-cancel" data-id="${esc(state.taskId)}">Cancel</button>`
            : '',
    ].filter(Boolean).join('');
}

export function initActivity({ mount, ws } = {}) {
    if (!mount) return { refresh: () => {} };
    let busy = false;
    let schedulesData = null;
    let tasksData = null;
    let stateData = null;
    let notice = null;
    const remoteStates = new Map();

    function stateForTask(task) {
        const taskId = taskIdOf(task);
        const previous = remoteStates.get(taskId);
        const state = previous
            ? mergeRemoteTaskState(previous, {}, task)
            : normalizeRemoteTaskState({}, task);
        if (taskId) remoteStates.set(taskId, state);
        return state;
    }

    function renderTaskRow(task, kind, queueRow = null) {
        const id = taskIdOf(task) || String(queueRow?.id || '');
        const placement = remotePlacementFromTask(task);
        const remoteState = placement ? stateForTask({ ...task, task_id: id }) : null;
        const runtime = kind === 'running' && queueRow?.runtime_sec != null
            ? ` · ${Math.round(queueRow.runtime_sec)}s`
            : '';
        const type = queueRow?.type ? ` · ${esc(queueRow.type)}` : '';
        const remoteMeta = remoteState ? ` · SSH ${esc(remoteStateSummary(remoteState))}` : '';
        const genericCancel = !remoteState
            ? `<button type="button" class="btn btn-xs btn-danger" data-act="task-cancel" data-id="${esc(id)}">Cancel</button>`
            : '';
        return `<div class="activity-row${remoteState ? ' activity-row-remote' : ''}" data-task-id="${esc(id)}">
            <div class="activity-row-main">
                <span class="activity-name">${esc(taskLabel(task, queueRow?.type || id || 'task'))}</span>
                <span class="activity-sub">${esc(kind)}${type}${runtime}${remoteMeta}</span>
                ${renderRemoteDetails(remoteState)}
            </div>
            <div class="activity-row-actions">
                ${renderRemoteStatus(remoteState)}
                ${renderRemoteActions(remoteState)}
                ${genericCancel}
            </div>
        </div>`;
    }

    function renderQueue(queue, durableTasks) {
        const running = Array.isArray(queue?.running) ? queue.running : [];
        const pending = Array.isArray(queue?.pending) ? queue.pending : [];
        const durableById = new Map(durableTasks.map((task) => [taskIdOf(task), task]));
        const row = (entry, kind) => {
            const queuedTask = entry?.task || {};
            const id = String(entry?.id || queuedTask.id || '');
            return renderTaskRow({ ...durableById.get(id), ...queuedTask, task_id: id }, kind, entry);
        };
        const parts = [...running.map((item) => row(item, 'running')), ...pending.map((item) => row(item, 'pending'))];
        return parts.length ? parts.join('') : '<div class="activity-empty">Nothing running or queued.</div>';
    }

    function renderRemoteTasks(queue, durableTasks) {
        const queuedIds = new Set([
            ...(Array.isArray(queue?.running) ? queue.running : []),
            ...(Array.isArray(queue?.pending) ? queue.pending : []),
        ].map((entry) => String(entry?.id || entry?.task?.id || '')));
        const rows = durableTasks
            .filter((task) => remotePlacementFromTask(task) && !queuedIds.has(taskIdOf(task)))
            .slice(0, 10)
            .map((task) => renderTaskRow(task, String(task.status || 'unknown')));
        return rows.length ? rows.join('') : '<div class="activity-empty">No recent SSH tasks.</div>';
    }

    function renderBg(data) {
        const enabled = Boolean(data?.bg_consciousness_enabled);
        const bg = data?.bg_consciousness_state || {};
        const detail = esc(bg.detail || bg.last_idle_reason || (enabled ? 'running' : 'disabled'));
        return `<div class="activity-row">
            <div class="activity-row-main">
                <span class="activity-name">Background consciousness</span>
                <span class="activity-sub">${enabled ? 'enabled' : 'disabled'}${detail ? ` · ${detail}` : ''}</span>
            </div>
            <div class="activity-row-actions">
                <button type="button" class="btn btn-xs btn-default" data-act="bg-toggle" data-enabled="${enabled ? '1' : '0'}"${ws ? '' : ' disabled'}>${enabled ? 'Stop' : 'Start'}</button>
            </div>
        </div>`;
    }

    function renderSchedules(data) {
        const tasks = Array.isArray(data?.tasks) ? data.tasks : [];
        if (!tasks.length) return '<div class="activity-empty">No scheduled tasks.</div>';
        return tasks.map((schedule) => {
            const managed = isSkillManaged(schedule);
            const cron = esc(schedule.trigger?.expr || schedule.cron || '');
            const next = esc(schedule.next_run_at || '');
            const enabled = schedule.enabled !== false;
            const id = esc(schedule.id || '');
            const sub = `${cron}${next ? ` · next ${next}` : ''}${managed && schedule.skill ? ` · ${esc(schedule.skill)}` : ''}`;
            const actions = managed
                ? '<span class="activity-tag">managed by skill</span>'
                : `<button type="button" class="btn btn-xs btn-default" data-act="schedule-toggle" data-id="${id}">${enabled ? 'Disable' : 'Enable'}</button>
                   <button type="button" class="btn btn-xs btn-danger" data-act="schedule-delete" data-id="${id}">Delete</button>`;
            return `<div class="activity-row${enabled ? '' : ' off'}">
                <div class="activity-row-main">
                    <span class="activity-name">${esc(schedule.name || schedule.id || 'schedule')}</span>
                    <span class="activity-sub">${sub}</span>
                </div>
                <div class="activity-row-actions">${actions}</div>
            </div>`;
        }).join('');
    }

    function render() {
        const durableTasks = Array.isArray(tasksData?.tasks) ? tasksData.tasks : [];
        mount.innerHTML = `
            <div class="activity-scroll">
                ${notice ? `<div class="activity-notice" data-tone="${esc(notice.tone)}" role="status">${esc(notice.text)}</div>` : ''}
                <div class="activity-section">
                    <h3 class="activity-h">Running &amp; queued</h3>
                    ${renderQueue(tasksData?.queue, durableTasks)}
                </div>
                <div class="activity-section">
                    <h3 class="activity-h">SSH tasks</h3>
                    ${renderRemoteTasks(tasksData?.queue, durableTasks)}
                </div>
                <div class="activity-section">
                    <h3 class="activity-h">Background</h3>
                    ${renderBg(stateData)}
                </div>
                <div class="activity-section">
                    <h3 class="activity-h">Scheduled (cron)</h3>
                    ${renderSchedules(schedulesData)}
                </div>
            </div>
        `;
    }

    async function refresh() {
        if (!tasksData) mount.innerHTML = '<div class="activity-loading">Loading activity…</div>';
        const [schedules, tasks, state] = await Promise.all([
            getJson('/api/schedules'),
            getJson('/api/tasks?limit=50'),
            getJson('/api/state'),
        ]);
        schedulesData = schedules;
        tasksData = tasks;
        stateData = state;
        render();
    }

    async function findSchedule(id) {
        const data = await getJson('/api/schedules');
        const tasks = Array.isArray(data?.tasks) ? data.tasks : [];
        return tasks.find((schedule) => String(schedule.id) === String(id)) || null;
    }

    function mergeLiveEvent(event, taskId = '') {
        const explicitTaskId = String(taskId || event?.task_id || '');
        if (explicitTaskId) {
            const task = (tasksData?.tasks || []).find((item) => taskIdOf(item) === explicitTaskId) || {
                task_id: explicitTaskId,
                status: event?.completion || '',
            };
            remoteStates.set(
                explicitTaskId,
                mergeRemoteTaskState(remoteStates.get(explicitTaskId), { ...event, task_id: explicitTaskId }, task),
            );
            return;
        }
        const connectionId = String(event?.connection_id || '');
        for (const [id, current] of remoteStates) {
            if (current.connectionId !== connectionId) continue;
            remoteStates.set(id, mergeRemoteTaskState(current, { ...event, task_id: id }, {
                task_id: id,
                status: current.taskStatus,
            }));
        }
    }

    mount.addEventListener('click', async (event) => {
        const btn = event.target.closest('[data-act]');
        if (!btn || busy) return;
        const act = btn.dataset.act;
        const id = btn.dataset.id || '';
        busy = true;
        btn.disabled = true;
        notice = null;
        try {
            if (act === 'task-cancel') {
                if (!window.confirm('Cancel this task?')) return;
                await apiClient.taskCancel(id);
                notice = { tone: 'ok', text: 'Cancellation requested.' };
            } else if (act === 'connection-reconnect') {
                const taskId = btn.dataset.taskId || '';
                mergeLiveEvent({
                    connection_id: id,
                    task_id: taskId,
                    status: 'connecting',
                    phase: 'connect',
                    completion: 'testing',
                });
                render();
                const result = await apiClient.connectionReconnect(id);
                mergeLiveEvent({ ...result, connection_id: id, task_id: taskId });
                const state = remoteStates.get(taskId);
                notice = {
                    tone: 'ok',
                    text: remoteTaskActions(state).terminal
                        ? 'Connection is ready. Start a new task to retry the completed attempt.'
                        : 'Connection reconnected and reconciled.',
                };
            } else if (act === 'schedule-delete') {
                if (!window.confirm('Delete this schedule?')) return;
                await apiFetch(`/api/schedules/${encodeURIComponent(id)}`, { method: 'DELETE' });
            } else if (act === 'schedule-toggle') {
                const rec = await findSchedule(id);
                if (rec) {
                    await apiFetch('/api/schedules', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ...rec, enabled: !(rec.enabled !== false) }),
                    });
                }
            } else if (act === 'bg-toggle') {
                const on = btn.dataset.enabled === '1';
                ws?.send?.({ type: 'command', cmd: `/bg ${on ? 'stop' : 'start'}` });
                await new Promise((resolve) => setTimeout(resolve, 400));
            }
        } catch (error) {
            const payload = error?.body || {};
            const taskId = btn.dataset.taskId || '';
            if (act === 'connection-reconnect') {
                mergeLiveEvent({ ...payload, connection_id: id, task_id: taskId, status: 'degraded' });
            }
            notice = {
                tone: 'warn',
                text: `${payload.error || error?.message || error}${payload.action ? ` · Next: ${payload.action}` : ''}`,
            };
        } finally {
            busy = false;
            await refresh();
        }
    });

    if (ws && typeof ws.on === 'function') {
        ws.on('connection_state', (event) => {
            mergeLiveEvent(event);
            if (tasksData) render();
        });
    }

    window.addEventListener('ouro:dashboard-subtab-shown', (event) => {
        if (event?.detail?.tab === 'activity') refresh();
    });

    return { refresh };
}
