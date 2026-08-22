/**
 * clearPatients.js — wipe patient data from a target database while keeping
 * ONLY admin accounts. Resets patient queue numbering.
 *
 * Decisions baked in:
 *   - Accounts:  keep ONLY admins (delete volunteer / non-admin profiles)
 *   - Numbering: reset (clears `counters` + `queueCounters` so next patient = queueNo 1)
 *
 * Safety:
 *   - Refuses to run unless you pass --db=<TARGET_DB> explicitly (won't use .env DB_NAME).
 *   - Dry run by default; only deletes when you add --confirm.
 *   - Identifies admins by boolean is_admin===true and deletes profiles by
 *     _id EXCLUSION of that exact set (not a loose filter).
 *   - ABORTS if any profile has a non-boolean is_admin (ambiguous — a human must decide).
 *   - ABORTS if it finds 0 admins.
 *   - Re-verifies after deletion that only the expected admins remain.
 *
 * Usage (from phs-app-backend/):
 *   node scripts/clearPatients.js --db=phs             # dry run — deletes nothing
 *   node scripts/clearPatients.js --db=phs --confirm   # actually clears
 */
const { MongoClient } = require("mongodb");
require("dotenv").config();

async function run() {
  const args = process.argv.slice(2);
  const confirm = args.includes("--confirm");
  const dbArg = (args.find((a) => a.startsWith("--db=")) || "").split("=")[1];

  if (!dbArg) {
    console.error(`Refusing to run. Pass the target database explicitly, e.g. --db=phs`);
    console.error(`(Your .env DB_NAME is ignored on purpose so this can't hit the wrong DB.)`);
    process.exit(1);
  }
  const TARGET_DB = dbArg;
  if (!process.env.MONGODB_URI) {
    console.error("MONGODB_URI is not set in .env");
    process.exit(1);
  }

  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  try {
    const db = client.db(TARGET_DB);
    const profiles = db.collection("profiles");

    // ---- 1. Work out exactly which accounts are kept vs deleted ----
    const totalProfiles = await profiles.countDocuments({});
    const admins = await profiles
      .find({ is_admin: true }) // strict boolean true
      .project({ username: 1 })
      .toArray();
    const adminIds = admins.map((a) => a._id);

    // Anything whose is_admin exists but isn't a real boolean is AMBIGUOUS.
    const ambiguous = await profiles
      .find({ is_admin: { $exists: true, $nin: [true, false] } })
      .project({ username: 1, is_admin: 1 })
      .toArray();

    console.log(`\nDB: ${TARGET_DB}`);
    console.log(`profiles total: ${totalProfiles}`);
    console.log(`admins to KEEP (${admins.length}): ${admins.map((a) => a.username).join(", ") || "—"}`);
    console.log(`profiles to DELETE: ${totalProfiles - admins.length}\n`);

    if (ambiguous.length > 0) {
      console.error(`ABORT: ${ambiguous.length} profile(s) have a non-boolean is_admin.`);
      console.error(`Fix or confirm these before running so none are deleted by mistake:`);
      ambiguous.forEach((a) => console.error(`   ${a.username}: is_admin = ${JSON.stringify(a.is_admin)}`));
      process.exit(1);
    }
    if (admins.length === 0) {
      console.error("ABORT: found 0 admins — refusing to proceed.");
      process.exit(1);
    }

    // ---- 2. Clear every other collection (patient data + counters) ----
    const cols = await db.listCollections({}, { nameOnly: true }).toArray();
    for (const { name } of cols) {
      if (name === "profiles") continue; // handled separately below
      if (name.startsWith("system.")) continue; // never touch system collections
      const n = await db.collection(name).countDocuments({});
      if (!confirm) {
        console.log(`  clear? ${name} (${n})   [dry run]`);
      } else {
        const { deletedCount } = await db.collection(name).deleteMany({});
        console.log(`  CLEAR  ${name} (${deletedCount})`);
      }
    }

    // ---- 3. Prune profiles down to the admins we identified ----
    if (!confirm) {
      console.log(`\n  profiles: would KEEP ${admins.length} admins, DELETE ${totalProfiles - admins.length}`);
      console.log(`\nDry run only. Nothing was deleted. Re-run with --confirm to execute.`);
      return;
    }

    const { deletedCount } = await profiles.deleteMany({ _id: { $nin: adminIds } });
    const totalAfter = await profiles.countDocuments({});
    const adminsAfter = await profiles.countDocuments({ is_admin: true });
    const nonAdminsAfter = totalAfter - adminsAfter;

    console.log(`\n  profiles: deleted ${deletedCount}; remaining ${totalAfter} (admins ${adminsAfter})`);
    const ok = adminsAfter === admins.length && totalAfter === admins.length && nonAdminsAfter === 0;
    console.log(ok ? "✅ Only the expected admins remain — accounts intact." : "❌ MISMATCH — investigate immediately.");
    console.log(`(Patient queue numbering will restart at 1 on the next registration.)`);
  } finally {
    await client.close();
  }
}

run().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
