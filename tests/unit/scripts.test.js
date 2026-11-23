/**
 * The release tooling must itself be valid JavaScript.
 *
 * WHY THIS EXISTS: on 23.11.2026 a broken string literal in scripts/ship.mjs
 * survived every green test run — 279 unit, 108 QA, 81 security, 44 RLS, all
 * passing — because nothing in the suite ever loaded the release script. It was
 * found by a person typing `npm run ship` and getting a SyntaxError instead of
 * a deploy.
 *
 * The scripts are the least-exercised code in the repo and the most annoying to
 * have broken: they are run by hand, usually once, usually at the moment you
 * want to release. A parse check is cheap and catches the entire class.
 *
 * This asserts syntax, not behaviour. Running ship.mjs for real would push to
 * production, and running migrations.mjs needs credentials — but "does it
 * parse" is exactly the failure that happened, and it costs milliseconds.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'

const SCRIPTS = fileURLToPath(new URL('../../scripts', import.meta.url))

const files = readdirSync(SCRIPTS).filter(f => /\.(mjs|cjs|js)$/.test(f))

test('the scripts directory was actually found', () => {
  assert.ok(files.length >= 5, `only found ${files.length} scripts — is the path right?`)
})

for (const f of files) {
  test(`scripts/${f} parses`, () => {
    try {
      // --check parses without executing: no deploy, no network, no writes.
      execFileSync(process.execPath, ['--check', join(SCRIPTS, f)], { stdio: 'pipe' })
    } catch (e) {
      const detail = (e.stderr?.toString() || e.message).split('\n').slice(0, 6).join('\n')
      assert.fail(`scripts/${f} is not valid JavaScript:\n${detail}`)
    }
  })
}

/**
 * NOT TESTED HERE: ship.mjs's behaviour.
 *
 * The first version of this file imported it to unit-test its diagnose()
 * helper. ship.mjs is a SCRIPT, not a module — importing it RUNS it, and a
 * release script run from a test is a release. It stopped only because the
 * working tree happened to be dirty; on a clean tree that import would have
 * started pushing to production.
 *
 * Anything in these scripts worth testing directly has to be extracted into a
 * module that imports cleanly first. Until then, `--check` in a child process
 * is the right boundary: it parses the file and executes nothing.
 */
