const CONNECTION_STATES = new Set([
    'connecting', 'ready', 'degraded', 'disconnected', 'unknown',
]);
const CANCELLABLE_TASK_STATES = new Set([
    'requested', 'connecting', 'scheduled', 'pending', 'running',
]);
const TERMINAL_TASK_STATES = new Set([
    'completed', 'failed', 'cancelled', 'rejected', 'rejected_duplicate',
    'interrupted', 'timed_out', 'timeout',
]);
const DETAIL_TEXT_LIMIT = 4000;
const DETAIL_COLLECTION_LIMIT = 32;

function text(value, limit = 512) {
    return String(value ?? '').replace(/\0/g, '').slice(0, limit);
}

function bounded(value, depth = 0) {
    if (depth >= 4) return '[truncated]';
    if (typeof value === 'string') return text(value, DETAIL_TEXT_LIMIT);
    if (value == null || ['boolean', 'number'].includes(typeof value)) return value;
    if (Array.isArray(value)) {
        return value.slice(0, DETAIL_COLLECTION_LIMIT).map((item) => bounded(item, depth + 1));
    }
    if (typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).slice(0, DETAIL_COLLECTION_LIMIT)
                .map(([key, item]) => [text(key, 128), bounded(item, depth + 1)]),
        );
    }
    return text(value, DETAIL_TEXT_LIMIT);
}

export function remotePlacementFromTask(task = {}) {
    const metadata = task?.metadata && typeof task.metadata === 'object' ? task.metadata : {};
    const sealed = metadata._sealed_workspace_ref && typeof metadata._sealed_workspace_ref === 'object'
        ? metadata._sealed_workspace_ref
        : {};
    const executor = metadata.executor_ref && typeof metadata.executor_ref === 'object'
        ? metadata.executor_ref
        : {};
    const connectionId = text(
        sealed.connection_id || (executor.type === 'ssh_exec' ? executor.id : ''),
    );
    if (!connectionId) return null;
    return {
        connectionId,
        projectId: text(task.project_id || metadata.project_id || ''),
        workspaceId: text(sealed.workspace_id || executor.workspace_id || ''),
    };
}

function inferredStatus(task = {}) {
    const taskStatus = text(task.status || task.remote_admission?.state || '').toLowerCase();
    const metadata = task?.metadata && typeof task.metadata === 'object' ? task.metadata : {};
    const hasAdmissionEvidence = (
        metadata._remote_admission_evidence
        && typeof metadata._remote_admission_evidence === 'object'
    );
    const hasPendingAdmission = (
        task.remote_admission
        && typeof task.remote_admission === 'object'
        && !hasAdmissionEvidence
    );
    if (
        ['requested', 'connecting', 'recovery_required'].includes(taskStatus)
        && hasPendingAdmission
    ) return 'connecting';
    if (['scheduled', 'pending', 'running'].includes(taskStatus) && hasAdmissionEvidence) {
        return 'ready';
    }
    // A generic task failure says nothing about SSH health. Only a task that
    // failed before admission evidence existed can be projected as degraded;
    // model/test failures after admission, and completed tasks after reload,
    // deliberately remain unknown without a live connection_state frame.
    if (taskStatus === 'failed' && hasPendingAdmission) return 'degraded';
    return 'unknown';
}

export function normalizeRemoteTaskState(event = {}, task = {}) {
    const placement = remotePlacementFromTask(task) || {};
    const rawStatus = text(event.status || '').toLowerCase();
    const hasTypedStatus = CONNECTION_STATES.has(rawStatus);
    const status = hasTypedStatus ? rawStatus : inferredStatus(task);
    const taskStatus = text(task.status || '').toLowerCase();
    const diagnostic = event.diagnostic && typeof event.diagnostic === 'object'
        ? bounded(event.diagnostic)
        : null;
    const logRefs = Array.isArray(event.log_refs)
        ? event.log_refs.slice(0, DETAIL_COLLECTION_LIMIT)
            .filter((item) => item && typeof item === 'object')
            .map((item) => bounded(item))
        : [];
    return {
        taskId: text(event.task_id || task.task_id || task.id || ''),
        connectionId: text(event.connection_id || placement.connectionId || ''),
        projectId: text(event.project_id || placement.projectId || ''),
        status,
        phase: text(event.phase || (status === 'connecting' ? 'admission' : '')),
        completion: text(event.completion || taskStatus || ''),
        errorCode: text(event.error_code || task.reason_code || ''),
        action: text(event.action || ''),
        diagnostic,
        logRefs,
        taskStatus,
        stateSource: hasTypedStatus
            ? 'live'
            : (status === 'degraded' ? 'admission' : 'derived'),
    };
}

export function mergeRemoteTaskState(previous = {}, event = {}, task = {}) {
    const next = normalizeRemoteTaskState(event, task);
    const has = (key) => Object.prototype.hasOwnProperty.call(event || {}, key);
    return {
        ...previous,
        ...next,
        status: has('status') ? next.status : (previous.status || next.status),
        phase: has('phase') ? next.phase : (previous.phase || next.phase),
        completion: has('completion')
            ? next.completion
            : (previous.completion || next.completion),
        errorCode: has('error_code')
            ? next.errorCode
            : (has('status') && next.status === 'ready'
                ? ''
                : (previous.errorCode || next.errorCode)),
        action: has('action')
            ? next.action
            : (has('status') && next.status === 'ready'
                ? ''
                : (previous.action || next.action)),
        stateSource: has('status')
            ? next.stateSource
            : (previous.stateSource || next.stateSource),
        diagnostic: next.diagnostic || previous.diagnostic || null,
        logRefs: next.logRefs.length ? next.logRefs : (previous.logRefs || []),
        taskStatus: next.taskStatus || previous.taskStatus || '',
    };
}

export function remoteTaskActions(state = {}) {
    const taskStatus = text(state.taskStatus || '').toLowerCase();
    const hasConnectionEvidence = ['live', 'admission'].includes(state.stateSource);
    const terminal = TERMINAL_TASK_STATES.has(taskStatus);
    return {
        canCancel: Boolean(state.taskId && CANCELLABLE_TASK_STATES.has(taskStatus || state.completion)),
        canReconnect: Boolean(
            state.connectionId
            && hasConnectionEvidence
            && (!terminal || taskStatus === 'failed')
            && ['degraded', 'disconnected', 'unknown'].includes(state.status),
        ),
        terminal,
    };
}

export function remoteStateLabel(status = '') {
    return ({
        connecting: 'Connecting',
        ready: 'Ready',
        degraded: 'Degraded',
        disconnected: 'Disconnected',
        unknown: 'Unknown',
    })[status] || 'Unknown';
}

export function remoteStateSummary(state = {}) {
    return [
        remoteStateLabel(state.status),
        state.phase ? `phase: ${state.phase}` : '',
        state.completion ? `completion: ${state.completion}` : '',
        state.errorCode ? `error: ${state.errorCode}` : '',
    ].filter(Boolean).join(' · ');
}

export function remoteStateDetails(state = {}) {
    const parts = [];
    if (state.diagnostic) parts.push({ label: 'Diagnostic', value: state.diagnostic });
    for (const ref of state.logRefs || []) {
        const label = text(ref.stream || ref.name || ref.kind || 'Full log', 80);
        parts.push({ label, value: ref });
    }
    return parts;
}

export function remoteDetailText(value, limit = 12000) {
    const rendered = JSON.stringify(value, null, 2) || '';
    return rendered.length > limit
        ? `${rendered.slice(0, limit)}\n… diagnostic preview truncated`
        : rendered;
}
