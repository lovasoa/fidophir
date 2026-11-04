// This privileged gate is loaded from main and never executes candidate code.
module.exports = async ({github, context, core}) => {
  const {owner, repo} = context.repo;
  const run = context.payload.workflow_run;
  if (run.conclusion !== 'success' || run.head_repository?.full_name !== `${owner}/${repo}`
      || run.path !== '.github/workflows/packages.yml'
      || !['pull_request', 'workflow_dispatch'].includes(run.event)) return;
  const branch = run.head_branch;
  const cargo = /^automation\/cargo-(compatible|major)$/.exec(branch);
  let pr;
  if (cargo) {
    if (run.actor?.login !== 'github-actions[bot]') return;
  } else if (branch.startsWith('dependabot/')) {
    const prs = (await github.rest.pulls.list({owner, repo, state: 'open', base: 'main', head: `${owner}:${branch}`})).data;
    pr = prs.find(p => p.user.login === 'dependabot[bot]' && p.head.sha === run.head_sha
      && p.head.repo?.full_name === `${owner}/${repo}`);
    if (!pr) return;
  } else return;
  const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRun, {owner, repo, run_id: run.id, filter: 'latest'});
  for (const name of ['Test and build Fedora 44 RPM', 'Build Debian 13 DEB']) {
    if (!jobs.some(j => j.name === name && j.conclusion === 'success')) return;
  }
  const ref = `heads/${branch}`;
  const head = (await github.rest.git.getRef({owner, repo, ref})).data.object.sha;
  if (head !== run.head_sha) return; // An old successful run cannot approve a new head.
  const compare = (await github.rest.repos.compareCommitsWithBasehead({owner, repo, basehead: `main...${head}`})).data;
  const allowed = cargo ? /^(Cargo\.toml|Cargo\.lock|locks\/opensk\.Cargo\.lock)$/
    : /^(\.github\/workflows\/[^/]+\.ya?ml|\.github\/images\/Dockerfile\.(rust|fedora)|vendor\/OpenSK)$/;
  const refresh = async () => {
    if (cargo) {
      await github.rest.actions.createWorkflowDispatch({owner, repo, workflow_id: 'dependencies.yml',
        ref: 'main', inputs: {track: cargo[1]}});
    } else {
      try {
        await github.rest.repos.merge({owner, repo, base: branch, head: 'main'});
        await github.rest.actions.createWorkflowDispatch({owner, repo, workflow_id: 'packages.yml', ref: branch});
      } catch (error) {
        if (error.status !== 409) throw error;
        core.warning('Dependency update conflicts with main; leaving it unmerged.');
      }
    }
  };
  if (!['ahead', 'identical'].includes(compare.status)) return refresh();
  if (!compare.files?.length || compare.files.length >= 300
      || compare.files.some(f => !allowed.test(f.filename) || f.previous_filename || f.status === 'removed')) return;
  let merged = head;
  try {
    if (cargo) {
      // Non-forced fast-forward atomically refuses a concurrent, untested main.
      await github.rest.git.updateRef({owner, repo, ref: 'heads/main', sha: head, force: false});
    } else {
      const result = await github.rest.pulls.merge({owner, repo, pull_number: pr.number, sha: head, merge_method: 'rebase'});
      if (!result.data.merged) throw new Error('Dependency PR was not merged');
      merged = result.data.sha;
    }
  } catch (error) {
    if (![409, 422].includes(error.status)) throw error;
    return refresh();
  }
  // GITHUB_TOKEN changes do not trigger push workflows. Dispatch explicitly,
  // naming the exact accepted commit even if main advances before dispatch.
  await github.rest.actions.createWorkflowDispatch({owner, repo, workflow_id: 'packages.yml',
    ref: 'main', inputs: {'source-sha': merged}});
};
