// make-page.mjs — assemble index.html from the PROVEN kernel + the UI + the template.
// The page inlines kernel.mjs verbatim, so the gated logic IS the live logic. CI regenerates and
// runs `git diff --exit-code index.html` — if the page ever drifts from the kernel, the build fails.
import { readFileSync, writeFileSync } from 'node:fs';

const kernel = readFileSync(new URL('./kernel.mjs', import.meta.url), 'utf8');
const ui = readFileSync(new URL('./ui.js', import.meta.url), 'utf8');
let tmpl = readFileSync(new URL('./page.template.html', import.meta.url), 'utf8');

const schema = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'SoftwareApplication',
      name: 'Kar-Warden',
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Any (runs in the browser)',
      description: 'Declare what an AI component is allowed to be — baseline config, capabilities, files, invariants — and prove, with no LLM judge, whether it still is: INTACT, DRIFTED or BREACHED, with a tamper-evident hash-chained log and a third-party re-runnable signed receipt.',
      url: 'https://sjgant80-hub.github.io/kar-warden/',
      isAccessibleForFree: true,
      creator: { '@type': 'Organization', name: 'FallForge estate (Kar / karma-didy)' },
      featureList: [
        'Deterministic integrity verdict (INTACT / DRIFTED / BREACHED) with no LLM judge',
        'One severe break is a breach and cannot be averaged away',
        'Hash-chained tamper-evident anomaly log',
        'Third-party re-runnable, Ed25519-signable receipts',
        'Runs entirely client-side — no data leaves the browser',
      ],
    },
    {
      '@type': 'FAQPage',
      mainEntity: [
        { '@type': 'Question', name: 'Is Kar-Warden an antivirus or a runtime sandbox?', acceptedAnswer: { '@type': 'Answer', text: 'No. It does not sit in the execution path or block anything. It is an attestation layer: given a declared warrant and an observed snapshot, it produces a provable, re-runnable verdict about whether they match.' } },
        { '@type': 'Question', name: 'Where does the observed state come from?', acceptedAnswer: { '@type': 'Answer', text: 'From wherever you inventory a component: its config hashed, its granted scopes listed, its files hashed, its runtime invariants read as booleans. Warden is the pure comparison and the proof; collecting the snapshot is the caller’s job.' } },
        { '@type': 'Question', name: 'Why no LLM judge?', acceptedAnswer: { '@type': 'Answer', text: 'A judge you cannot re-run is not proof. Every verdict is a deterministic comparison over hashes and booleans, so a third party gets the same answer byte-for-byte.' } },
        { '@type': 'Question', name: 'Is my data sent anywhere?', acceptedAnswer: { '@type': 'Answer', text: 'No. The kernel is inlined in the page and runs entirely in your browser. Nothing is uploaded; signing uses your browser’s own WebCrypto.' } },
      ],
    },
  ],
};

tmpl = tmpl.replace('<!--SCHEMA-->', '<script type="application/ld+json">\n' + JSON.stringify(schema, null, 2) + '\n</script>');
tmpl = tmpl.replace('//<!--KERNEL_AND_UI-->', kernel + '\n\n/* ── UI ── */\n' + ui);

writeFileSync(new URL('./index.html', import.meta.url), tmpl);
console.log('index.html written · kernel', kernel.length, 'bytes · ui', ui.length, 'bytes · total', tmpl.length, 'bytes');
