// Opt-in interoperability with the real Dash Worker, real SQLite and Miniflare
// R2. No production credentials, remote network, bots or mail are used.
// RBQ_DASH_SOURCE=/clean/dash RBQ_BINARY=/path/rbq node --test scripts/test_dash_cli.mjs
import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { mkdtemp, writeFile, readFile, mkdir, rm } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'

const source = process.env.RBQ_DASH_SOURCE
const binary = process.env.RBQ_BINARY
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
test('Linux CLI → private Dash MCP/HTTP → real SQLite and R2', { skip: !source || !binary, timeout: 60000 }, async t => {
  const load = path => import(pathToFileURL(resolve(source, path)))
  const { default: worker } = await load('worker/index.js')
  const { createD1 } = await load('test/d1.mjs')
  const require = createRequire(resolve(source, 'package.json'))
  const { Miniflare, convertV4MiniflareOptions } = require('miniflare')
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: 'export default { fetch() { return new Response("ok") } }', compatibilityDate: '2026-09-15', r2Buckets: ['RBQ_STORAGE', 'PIECES_LABS'] }))
  t.after(() => mf.dispose())
  const origin = 'https://dash.ragbaz.cc'
  const env = { DB: createD1(), SITE_ORIGIN: origin, RBQ_STORAGE: await mf.getR2Bucket('RBQ_STORAGE'), PIECES_LABS: await mf.getR2Bucket('PIECES_LABS'),
    AUTH: { async fetch(request) {
      const email = request.headers.get('cookie')?.match(/sid=([^;]+)/)?.[1]
      return Response.json({ authenticated: Boolean(email), account: { id: email, email }, elevated: true })
    } } }
  t.after(() => env.DB.raw.close())
  const manuscript = '\ufeffA private piece: α🙂\r\n'
  const pieceId = '33333333-3333-4333-8333-333333333333'
  const revision = '55555555-5555-4555-8555-555555555555'
  await env.PIECES_LABS.put('alice-only', JSON.stringify({ pads: [{ id: '44444444-4444-4444-8444-444444444444', pieces: [{ id: pieceId, revision, title: 'Private letter', kind: 'letter', draft: true, source: manuscript }] }] }))
  env.DB.raw.prepare('INSERT INTO pieces_labs_workspaces(owner,version,snapshot_key,updated_at) VALUES(?,?,?,1)').run(sha('alice@example.test'), 'v', 'alice-only')
  const issue = async (email, grants = {}) => {
    const response = await worker.fetch(new Request(origin + '/api/mcp', { method: 'POST', headers: { origin, cookie: `sid=${email}`, 'content-type': 'application/json' }, body: JSON.stringify({ rbqStorage: true, artifactsRead: true, ...grants }) }), env)
    assert.equal(response.status, 201)
    return response.json()
  }
  const alice = await issue('alice@example.test')
  const server = createServer(async (request, response) => {
    try {
      const chunks = []
      for await (const chunk of request) chunks.push(chunk)
      const body = Buffer.concat(chunks)
      const result = await worker.fetch(new Request(origin + request.url, { method: request.method, headers: request.headers, ...(body.length ? { body } : {}) }), env)
      response.writeHead(result.status, Object.fromEntries(result.headers))
      response.end(Buffer.from(await result.arrayBuffer()))
    } catch { response.writeHead(500); response.end() }
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections() }))
  const directory = await mkdtemp('/tmp/opencode/rbq-cli-dash-')
  t.after(() => rm(directory, { recursive: true, force: true }))
  const tokenFile = join(directory, 'token')
  await writeFile(tokenFile, alice.token, { mode: 0o600 })
  const localOrigin = `http://127.0.0.1:${server.address().port}`
  const id = new URL(alice.url).pathname.split('/').at(-1)
  const run = async (group, ...args) => {
    const endpoint = `${localOrigin}/${group === 'artifacts' ? 'mcp' : 'api/rbq'}/${id}`
    const { stdout, stderr } = await promisify(execFile)(binary, [group, '--endpoint', endpoint, '--token-file', tokenFile, ...args], { timeout: 20000 })
    assert(!stderr.includes(alice.token))
    return JSON.parse(stdout)
  }
  const sources = await run('artifacts', 'sources')
  assert.equal(sources.trusted, false)
  const factory = sources.factories.find(factory => factory.id === 'pieces')
  const page = await run('artifacts', 'list', '--factory-source', factory.source_id, '--factory-id', 'pieces', '--limit', '1')
  assert.equal(page.artifacts[0].title, 'Private letter')
  assert(!JSON.stringify(page).includes(manuscript))
  const reference = ['--source', page.artifacts[0].ref.source_id, '--id', page.artifacts[0].ref.id]
  const read = await run('artifacts', 'read-piece', ...reference, '--expected-revision', revision)
  assert.equal(read.source, manuscript)
  assert.equal(read.content_sha256, sha(manuscript))
  await assert.rejects(run('artifacts', 'read-piece', ...reference, '--expected-revision', 'changed'))
  assert.equal((await run('artifacts', 'provenance', ...reference)).trusted, false)
  const local = join(directory, 'local')
  const bytes = Buffer.from('binary\0snapshot\r\n')
  const digest = sha(bytes)
  const content = sha(`data.txt\0${digest}\n`)
  const snapshot = `local/20261119T120000.000Z-${content.slice(0, 12)}`
  const chunkKey = `frog/v1/chunks/sha256/${digest.slice(0, 2)}/${digest}`
  const manifestKey = `frog/v1/snapshots/${snapshot}.json`
  for (const [key, value] of [[chunkKey, bytes], [manifestKey, JSON.stringify({ schema: 'rbq.layer.snapshot.v1', layer: 'frog', id: snapshot, label: 'local', created_at: '2026-11-19T12:00:00Z', run_id: null, chunk_bytes: 65536, digest: content, files: [{ path: 'data.txt', sha256: digest, bytes: bytes.length, chunks: [{ sha256: digest, size: bytes.length }] }], owner: { fixture: true } })]]) {
    const path = join(local, key)
    await mkdir(resolve(path, '..'), { recursive: true })
    await writeFile(path, value)
  }
  const push = ['push', '--store', local, '--source-id', 'laptop-uuid', '--source-name', 'Laptop', '--layer', 'frog']
  assert.equal((await run('repository', ...push)).transferred, 2)
  assert.equal((await run('repository', ...push)).transferred, 0)
  const arrivals = await run('artifacts', 'arrivals')
  assert.equal(arrivals.events.length, 1)
  assert.equal(arrivals.events[0].kind, 'sync.artifact.arrived')
  assert.equal(arrivals.events[0].ref.source_id, 'laptop-uuid')
  const watched = await run('artifacts', 'watch', '--batches', '1')
  assert.equal(watched.next_after, arrivals.next_after)
  assert.equal(watched.desktop_notification, undefined) // Opt-in only; no visible test notifications.
  assert.equal((await run('repository', 'sources')).sources[0].name, 'Laptop')
  const destination = join(directory, 'destination')
  const pull = ['pull', '--store', destination, '--source-id', 'laptop-uuid', '--layer', 'frog']
  const pulled = await run('repository', ...pull)
  assert.equal(pulled.complete, true)
  assert.equal(pulled.transferred, 2)
  assert.deepEqual(await readFile(join(destination, 'sources/v1/laptop-uuid/objects', chunkKey)), bytes)
  assert.equal((await run('repository', ...pull)).transferred, 0)
  const bob = await issue('bob@example.test')
  await writeFile(tokenFile, bob.token)
  // Endpoint ownership and token ownership must match, even for empty listings.
  await assert.rejects(run('repository', 'sources'))
  await assert.rejects(run('artifacts', 'get', ...reference))
  await writeFile(tokenFile, alice.token)
  await issue('alice@example.test') // rotation revokes old endpoint/token
  await assert.rejects(run('artifacts', 'sources'))
  await assert.rejects(run('repository', 'describe'))
})
