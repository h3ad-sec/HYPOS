let _db = null;

export async function loadHypDB() {
  try {
    const r = await fetch('./data/hyp-db.json');
    if (r.ok) _db = await r.json();
  } catch (_) {}
}

export function getCurated(techniqueId) {
  return _db?.techniques?.[techniqueId]?.hypotheses || null;
}
