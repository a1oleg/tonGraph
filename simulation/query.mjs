// query.mjs — run CYPHER_QUERIES.md checks against Neo4j Aura
// Usage: node simulation/query.mjs [sessionId]

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import neo4j from 'neo4j-driver';

const __dir = path.dirname(fileURLToPath(import.meta.url));

function loadEnv(envPath) {
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const m = line.match(/^([^#=]+)=(.*)$/);
    if (m) process.env[m[1].trim()] = m[2].trim();
  }
}

loadEnv(path.join(__dir, '../.env'));

const URI  = process.env.AURA_NEO4J_URI;
const USER = process.env.AURA_NEO4J_USER;
const PASS = process.env.AURA_NEO4J_PASSWORD;
const DB   = process.env.AURA_NEO4J_DATABASE || 'neo4j';

const sid = process.argv[2];
if (!sid) { console.error('Usage: node query.mjs <sessionId>'); process.exit(1); }

const driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASS));
const session = driver.session({ database: DB });

async function run(label, query, params = {}) {
  console.log(`\n── ${label} ${'─'.repeat(Math.max(0, 60 - label.length))}`);
  try {
    const result = await session.run(query, params);
    if (result.records.length === 0) {
      console.log('  (no results)');
    } else {
      const keys = result.records[0].keys;
      console.log('  ' + keys.join('\t'));
      for (const rec of result.records) {
        const vals = keys.map(k => {
          const v = rec.get(k);
          return v === null ? 'null' : String(neo4j.isInt(v) ? v.toNumber() : v);
        });
        console.log('  ' + vals.join('\t'));
      }
    }
  } catch (e) {
    console.log(`  ERROR: ${e.message}`);
  }
}

try {
  // ── Graph overview ──────────────────────────────────────────────────────────
  await run('#all-nodes — node types in session', `
    MATCH (n)
    WHERE n.sessionId = $sid
    RETURN labels(n)[0] AS type, count(n) AS cnt
    ORDER BY cnt DESC
  `, { sid });

  // ── Skip rate (liveness) ────────────────────────────────────────────────────
  await run('#skip-rate — liveness metric', `
    OPTIONAL MATCH (v:Validator)-[rs:skip]->(s:SkipEvent)
    WHERE s.sessionId = $sid
    OPTIONAL MATCH (v2:Validator)-[rn:notarize]->(c:Candidate)
    WHERE c.sessionId = $sid
    RETURN
      count(DISTINCT rs.slot) AS skippedSlots,
      count(DISTINCT rn.slot) AS notarizedSlots
  `, { sid });

  // ── Safety anomalies ────────────────────────────────────────────────────────
  await run('#alarm-skip-after-notarize — bug: SkipVote when votedNotar=true', `
    MATCH (a:AlarmSkip)
    WHERE a.sessionId = $sid AND a.votedNotar = true
    RETURN a.slot AS slot, a.tsMs AS ts
    ORDER BY slot
  `, { sid });

  await run('#amnesia-gap — VoteIntentSet without VoteIntentPersisted', `
    MATCH (vi:VoteIntent)
    WHERE vi.sessionId = $sid AND vi.persisted = false
    RETURN vi.slot AS slot, vi.candidateId AS candidateId, vi.tsMs AS intentTs
    ORDER BY slot
  `, { sid });

  await run('#dual-cert-issued — two FinalizeCerts on same slot', `
    MATCH (c1:CertIssued {certType: 'finalize'}), (c2:CertIssued {certType: 'finalize'})
    WHERE c1.sessionId = $sid AND c2.sessionId = $sid
      AND c1.slot = c2.slot AND c1.candidateId <> c2.candidateId
    RETURN c1.slot AS slot, c1.candidateId AS cand1, c2.candidateId AS cand2,
           c1.tsMs AS ts1, c2.tsMs AS ts2
  `, { sid });

  await run('#candidate-duplicate — Byzantine: two candidates from one leader', `
    MATCH (cd:CandidateDuplicate)
    WHERE cd.sessionId = $sid
    RETURN cd.slot AS slot, cd.leaderIdx AS leader,
           cd.existingCandId AS cand1, cd.newCandId AS cand2,
           cd.receiverIdx AS detectedBy
    ORDER BY slot
  `, { sid });

  await run('#equivocation — double notarize vote in same slot', `
    MATCH (v:Validator)-[r1:notarize]->(c1:Candidate),
          (v)-[r2:notarize]->(c2:Candidate)
    WHERE r1.slot = r2.slot
      AND c1.candidateId <> c2.candidateId
      AND r1.sessionId = r2.sessionId AND r1.sessionId = $sid
    RETURN v.validatorIdx AS validator, r1.slot AS slot,
           c1.candidateId AS candidate1, c2.candidateId AS candidate2
    ORDER BY slot
  `, { sid });

  await run('#conflict-tolerated — conflicts silenced on bootstrap replay', `
    MATCH (ct:ConflictTolerated)
    WHERE ct.sessionId = $sid
    RETURN ct.slot AS slot, ct.validatorIdx AS validator,
           ct.voteType AS voteType, ct.tsMs AS ts
    ORDER BY slot
  `, { sid });

  // ── Resource exhaustion ─────────────────────────────────────────────────────
  await run('#msg-flood — messages per source validator', `
    MATCH (src:Validator)-[r:recv]->(loc:Validator)
    WHERE r.sessionId = $sid
    RETURN src.validatorIdx AS source, loc.validatorIdx AS local,
           count(r) AS msgCount, min(r.slot) AS firstSlot, max(r.slot) AS lastSlot
    ORDER BY msgCount DESC
  `, { sid });

  await run('#notarize-weight-growth — distinct candidates per slot', `
    MATCH (r:ResourceLoad)
    WHERE r.sessionId = $sid
    RETURN r.slot AS slot,
           max(r.notarizeWeightEntries) AS maxCandidates,
           max(r.pendingRequests)       AS maxPending
    ORDER BY maxCandidates DESC, slot
  `, { sid });

  // ── Latency ─────────────────────────────────────────────────────────────────
  await run('#latency — first receive→accept per slot', `
    MATCH (cr:CandidateRecv)
    WHERE cr.sessionId = $sid
    MATCH (ba:BlockAccepted)
    WHERE ba.sessionId = $sid AND ba.slot = cr.slot AND ba.candidateId = cr.candidateId
    RETURN cr.slot AS slot,
           min(cr.tsMs) AS firstReceiveTs,
           ba.tsMs AS acceptTs,
           (ba.tsMs - min(cr.tsMs)) AS latencyMs
    ORDER BY slot
  `, { sid });

  // ── CertIssued summary ──────────────────────────────────────────────────────
  await run('#cert-issued — notarize/finalize certs per slot', `
    MATCH (ci:CertIssued)
    WHERE ci.sessionId = $sid
    RETURN ci.slot AS slot, ci.certType AS type, ci.weight AS weight,
           ci.candidateId AS candidateId, ci.tsMs AS ts
    ORDER BY slot, type
  `, { sid });

} finally {
  await session.close();
  await driver.close();
}
