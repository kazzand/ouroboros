import test from 'node:test';
import assert from 'node:assert/strict';

import {
    connectionStatusCopy,
    isSelectableRemoteConnection,
} from '../modules/connections_ui.js';
import { makeSshWorkspaceRef } from '../modules/project_create.js';

test('project picker requires current-process bootstrap evidence and fresh ready health', () => {
    assert.equal(isSelectableRemoteConnection({
        lifecycle: 'active',
        status: 'ready',
        bootstrap_compatible: true,
        health_fresh: true,
    }), true);
    assert.equal(isSelectableRemoteConnection({
        lifecycle: 'active',
        status: 'ready',
        expected_host_id: 'pinned-host',
        bootstrap_compatible: false,
        health_fresh: true,
    }), false);
    assert.equal(isSelectableRemoteConnection({
        lifecycle: 'active',
        status: 'ready',
        bootstrap_compatible: true,
        health_fresh: false,
    }), false);
    assert.equal(isSelectableRemoteConnection({
        lifecycle: 'active',
        status: 'degraded',
        expected_host_id: 'pinned-host',
        bootstrap_compatible: true,
        health_fresh: true,
    }), false);
    assert.equal(isSelectableRemoteConnection({
        lifecycle: 'retired',
        status: 'ready',
        bootstrap_compatible: true,
        health_fresh: true,
    }), false);
});

test('connection status copy keeps phase and typed error visible', () => {
    assert.equal(
        connectionStatusCopy({
            status: 'degraded',
            phase: 'handshake',
            error_code: 'incompatible_protocol',
        }),
        'degraded · phase: handshake · error: incompatible_protocol',
    );
});

test('connection status copy exposes neutralized SSH alias directives', () => {
    assert.equal(
        connectionStatusCopy({
            status: 'ready',
            phase: 'connect',
            warnings: [{
                code: 'ssh_alias_forwarding_neutralized',
                directives: ['localforward'],
            }],
        }),
        'ready · phase: connect · warning: ssh_alias_forwarding_neutralized',
    );
});

test('SSH Project request contains placement only after both selections exist', () => {
    assert.deepEqual(
        makeSshWorkspaceRef(' conn-1 ', ' /srv/project '),
        {
            kind: 'ssh',
            connection_id: 'conn-1',
            remote_root: '/srv/project',
        },
    );
    assert.equal(makeSshWorkspaceRef('', '/srv/project'), null);
    assert.equal(makeSshWorkspaceRef('conn-1', ''), null);
});
