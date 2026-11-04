const test = require('node:test');
const assert = require('node:assert/strict');
const merge = require('../tools/dependency-merge.cjs');

function fixture(options = {}) {
  const head = 'a'.repeat(40);
  const branch = options.dependabot ? 'dependabot/docker/rust' : 'automation/cargo-compatible';
  const calls = [];
  const run = {id: 12, conclusion: 'success', head_repository: {full_name: 'owner/repo'},
    path: '.github/workflows/packages.yml', event: 'workflow_dispatch', head_branch: branch,
    head_sha: head, actor: {login: 'github-actions[bot]'}};
  const api = {
    git: {
      getRef: async () => ({data: {object: {sha: options.currentHead || head}}}),
      updateRef: async args => {
        calls.push(['fast-forward', args]);
        if (options.race) throw Object.assign(new Error('Non-fast-forward'), {status: 422});
      },
    },
    actions: {
      getWorkflowRun: async () => ({data: run}),
      listJobsForWorkflowRun: () => {},
      createWorkflowDispatch: async args => calls.push(['dispatch', args]),
    },
    repos: {
      compareCommitsWithBasehead: async () => ({data: {status: options.status || 'ahead',
        files: options.files || [{filename: options.dependabot ? 'packaging/images/rust/Dockerfile' : 'Cargo.lock', status: 'modified'}]}}),
      merge: async args => calls.push(['refresh', args]),
    },
    pulls: {
      list: async () => ({data: [{number: 3, user: {login: options.author || 'dependabot[bot]'},
        head: {sha: head, repo: {full_name: 'owner/repo'}}}]}),
      merge: async args => { calls.push(['merge-pr', args]); return {data: {merged: true, sha: 'b'.repeat(40)}}; },
    },
  };
  const github = {rest: api, paginate: async () => [
    {name: 'Test and build Fedora 44 RPM', conclusion: 'success'},
    {name: 'Build Debian 13 DEB', conclusion: options.deb || 'success'},
  ]};
  const context = {repo: {owner: 'owner', repo: 'repo'}, payload: {workflow_run: {id: run.id}}};
  return {run, calls, execute: () => merge({github, context, core: {warning: () => {}}})};
}

test('only the tested Cargo head is fast-forwarded; exact commit is published explicitly', async () => {
  const f = fixture(); await f.execute();
  assert.deepEqual(f.calls.map(c => c[0]), ['fast-forward', 'dispatch']);
  assert.equal(f.calls[0][1].force, false);
  assert.equal(f.calls[1][1].inputs['source-sha'], f.run.head_sha);
});

test('failure, forks, wrong workflows/actors and skipped package builds cannot merge', async () => {
  for (const change of [r => r.conclusion = 'failure', r => r.head_repository.full_name = 'fork/repo',
    r => r.path = '.github/workflows/spoof.yml', r => r.actor.login = 'someone',
    r => r.head_branch = 'feature/untrusted', r => r.event = 'push']) {
    const f = fixture(); change(f.run); await f.execute(); assert.deepEqual(f.calls, []);
  }
  for (const deb of ['skipped', 'failure', 'cancelled', null]) {
    const f = fixture({deb: deb ?? 'skipped'}); await f.execute(); assert.deepEqual(f.calls, []);
  }
});

test('superseded runs and changes outside dependency files cannot merge', async () => {
  for (const options of [{currentHead: 'c'.repeat(40)}, {files: [{filename: 'src/tpm.rs'}]},
    {files: [{filename: 'Cargo.lock', status: 'removed'}]},
    {files: [{filename: 'Cargo.lock', previous_filename: 'src/main.rs'}]}]) {
    const f = fixture(options); await f.execute(); assert.deepEqual(f.calls, []);
  }
});

test('stale or racing Cargo updates are regenerated; no untested merge or publication', async () => {
  for (const options of [{status: 'diverged'}, {race: true}]) {
    const f = fixture(options); await f.execute();
    const dispatch = f.calls.at(-1)[1];
    assert.equal(dispatch.workflow_id, 'dependencies.yml');
    assert.equal(dispatch.inputs.track, 'compatible');
  }
});

test('only actual Dependabot PRs merge, guarded by their tested head', async () => {
  const rejected = fixture({dependabot: true, author: 'someone'});
  await rejected.execute(); assert.deepEqual(rejected.calls, []);
  const f = fixture({dependabot: true}); await f.execute();
  assert.equal(f.calls[0][0], 'merge-pr');
  assert.equal(f.calls[0][1].sha, f.run.head_sha);
  assert.equal(f.calls[1][1].inputs['source-sha'], 'b'.repeat(40));
});

test('stale Dependabot branches are refreshed and retested without publication', async () => {
  const f = fixture({dependabot: true, status: 'diverged'}); await f.execute();
  assert.deepEqual(f.calls.map(c => c[0]), ['refresh', 'dispatch']);
  assert.equal(f.calls[1][1].ref, f.run.head_branch);
  assert.equal(f.calls[1][1].inputs, undefined);
});
