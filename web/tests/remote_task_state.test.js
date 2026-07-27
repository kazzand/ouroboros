import test from 'node:test';
import assert from 'node:assert/strict';

import {
    mergeRemoteTaskState,
    normalizeRemoteTaskState,
    remoteDetailText,
    remotePlacementFromTask,
    remoteStateDetails,
    remoteStateLabel,
    remoteStateSummary,
    remoteTaskActions,
} from '../modules/remote_task_state.js';

const remoteTask = {
    task_id: 'task-1',
    project_id: 'project-1',
    status: 'requested',
    remote_admission: {
        admission_id: 'admission-1',
        state: 'requested',
    },
    metadata: {
        _sealed_workspace_ref: {
            kind: 'ssh',
            connection_id: 'connection-1',
            workspace_id: 'workspace-1',
        },
    },
};

test('durable requested SSH task derives connecting without changing local task shape', () => {
    assert.deepEqual(remotePlacementFromTask(remoteTask), {
        connectionId: 'connection-1',
        projectId: 'project-1',
        workspaceId: 'workspace-1',
    });
    const state = normalizeRemoteTaskState({}, remoteTask);
    assert.equal(state.status, 'connecting');
    assert.equal(state.taskStatus, 'requested');
    assert.deepEqual(remoteTaskActions(state), {
        canCancel: true,
        canReconnect: false,
        terminal: false,
    });
});

test('typed remote failure preserves bounded diagnostics and full-log references', () => {
    const state = normalizeRemoteTaskState({
        type: 'connection_state',
        connection_id: 'connection-1',
        task_id: 'task-1',
        status: 'degraded',
        phase: 'connect',
        completion: 'failed',
        error_code: 'permission_denied',
        diagnostic: {
            domain: 'filesystem',
            code: 'permission_denied',
            details: { stderr: 'permission denied' },
        },
        log_refs: [{ stream: 'stderr', blob_id: 'log-1', size: 5000 }],
    }, { ...remoteTask, status: 'failed' });
    assert.equal(
        remoteStateSummary(state),
        'Degraded · phase: connect · completion: failed · error: permission_denied',
    );
    assert.equal(remoteStateDetails(state).length, 2);
    assert.deepEqual(remoteTaskActions(state), {
        canCancel: false,
        canReconnect: true,
        terminal: true,
    });
});

test('connection-wide reconnect retains task identity and never implies task replay', () => {
    const failed = normalizeRemoteTaskState({
        connection_id: 'connection-1',
        task_id: 'task-1',
        status: 'degraded',
        completion: 'failed',
        error_code: 'ssh_timeout',
    }, { ...remoteTask, status: 'failed' });
    const ready = mergeRemoteTaskState(failed, {
        connection_id: 'connection-1',
        task_id: 'task-1',
        status: 'ready',
        completion: 'reconciled',
    }, { ...remoteTask, status: 'failed' });
    assert.equal(ready.status, 'ready');
    assert.equal(ready.errorCode, '');
    assert.equal(ready.taskStatus, 'failed');
    assert.equal(remoteTaskActions(ready).terminal, true);
    assert.equal(remoteTaskActions(ready).canReconnect, false);
    const refreshed = mergeRemoteTaskState(ready, {}, {
        ...remoteTask,
        status: 'failed',
    });
    assert.equal(refreshed.status, 'ready');
    assert.equal(refreshed.taskStatus, 'failed');
});

test('generic model/test failure and completed reload never invent SSH health', () => {
    const admitted = {
        ...remoteTask,
        remote_admission: {
            admission_id: 'admission-1',
            state: 'requested',
        },
        metadata: {
            ...remoteTask.metadata,
            _remote_admission_evidence: { host_id: 'host-1' },
        },
    };
    assert.equal(normalizeRemoteTaskState({}, {
        ...admitted,
        status: 'failed',
        reason_code: 'model_error',
    }).status, 'unknown');
    assert.equal(remoteTaskActions(normalizeRemoteTaskState({}, {
        ...admitted,
        status: 'failed',
        reason_code: 'model_error',
    })).canReconnect, false);
    assert.equal(normalizeRemoteTaskState({}, {
        ...admitted,
        status: 'completed',
    }).status, 'unknown');
    assert.equal(normalizeRemoteTaskState({}, {
        ...remoteTask,
        status: 'failed',
        reason_code: 'ssh_timeout',
    }).status, 'degraded');
});

test('diagnostic previews are bounded before rendering', () => {
    const state = normalizeRemoteTaskState({
        status: 'degraded',
        diagnostic: { message: 'x'.repeat(9000) },
        log_refs: Array.from({ length: 100 }, (_, idx) => ({ name: `log-${idx}` })),
    }, remoteTask);
    assert.equal(state.diagnostic.message.length, 4000);
    assert.equal(state.logRefs.length, 32);
    assert.match(remoteDetailText({ value: 'x'.repeat(20000) }), /preview truncated$/);
});

test('all connection contract states have stable UI labels', () => {
    assert.deepEqual(
        ['connecting', 'ready', 'degraded', 'disconnected', 'unknown']
            .map(remoteStateLabel),
        ['Connecting', 'Ready', 'Degraded', 'Disconnected', 'Unknown'],
    );
});
