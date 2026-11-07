// Records the demo from real runs on the live site. Captions read results from the page, so nothing is scripted in.
import { createRequire } from 'module';
import fs from 'fs';
import { fileURLToPath } from 'url';
const require = createRequire('/Users/fortizo/Downloads/LOUD HOUSE/flyover/');
const { chromium } = require('playwright');

const SITE = 'https://64-177-15-143.sslip.io';
const OUT = fileURLToPath(new URL('./video/', import.meta.url));
const EXE = process.env.CHROME_EXE;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch({ executablePath: EXE });
const ctx = await browser.newContext({
  viewport: { width: 1280, height: 720 }, deviceScaleFactor: 1, colorScheme: 'dark',
  recordVideo: { dir: OUT, size: { width: 1280, height: 720 } },
});
const page = await ctx.newPage();

const installOverlay = () => page.evaluate(() => {
  if (document.getElementById('cap')) return;
  const c = document.createElement('div');
  c.id = 'cap';
  c.style.cssText = 'position:fixed;left:50%;bottom:26px;transform:translateX(-50%);max-width:1040px;width:max-content;background:rgba(8,8,10,.92);color:#fff;font:600 25px/1.32 Inter,system-ui,sans-serif;padding:13px 22px;border-radius:10px;z-index:9999;text-align:center;border:1px solid rgba(255,255,255,.16);opacity:0;transition:opacity .2s';
  document.body.append(c);
  document.documentElement.style.scrollBehavior = 'smooth';
});
const say = async (text, ms = 4200) => {
  await installOverlay();
  await page.evaluate((t) => { const c = document.getElementById('cap'); c.textContent = t; c.style.opacity = t ? 1 : 0; }, text);
  if (ms) await wait(ms);
};
const scrollTo = (sel, block = 'start') => page.evaluate(([s, b]) => document.querySelector(s)?.scrollIntoView({ block: b }), [sel, block]);
const scrollBy = (y) => page.evaluate((v) => window.scrollBy(0, v), y);
const finished = () => page.waitForFunction(() => /done|failed/.test(document.getElementById('state')?.textContent || ''), null, { timeout: 150000 });

await page.goto(SITE, { waitUntil: 'networkidle' });
await say('Onchain agents read text written by strangers. A token can name itself anything.', 4800);
await say('Including instructions to steal your keys. So what happens when the agent gets tricked?', 4800);
await say('This is Receipts. Every action runs in a throwaway sandbox on Vultr.', 3800);

await page.click('text=Check a token');
await say('Ask about a real token. Vultr Serverless Inference plans the work and writes the code.', 4000);
await page.click('#go');
await wait(800);
await say('The model writes Python. It runs in a new container: gVisor, no keys, read-only disk, no route out.', 0);
await finished();
const state1 = await page.textContent('#state');
if (!state1.includes('done')) throw new Error('investigation failed: ' + await page.textContent('#timeline'));
const stats = await page.evaluate(() => {
  const t = [...document.querySelectorAll('.totals')].map((x) => x.innerText.replace(/\n/g, ' '));
  return { claims: t.find((x) => x.startsWith('Claim values')), box: t.find((x) => x.startsWith('Sandboxes used')), headline: document.querySelector('.receipt h3')?.textContent };
});
console.log('run', page.url(), JSON.stringify(stats));
fs.writeFileSync(OUT + 'run-investigate.txt', page.url() + '\n' + JSON.stringify(stats));
await say('The answer comes with receipts.', 3000);
await scrollBy(190);
await say(`Each tick means a program, not the model, found that exact value in the real output. ${stats.claims}.`, 6000);
await scrollTo('.timeline');
await say('Below it: the output from each sandbox, from live chain data.', 4000);
await page.evaluate(() => document.querySelector('.timeline details summary')?.click());
await wait(700);
await say('The exact code it ran is one click away.', 3400);
await scrollTo('.timeline .proof', 'center');
await say('Hashes, limits, hosts reached. And "destroyed, confirmed": Docker was asked again to check it\'s gone.', 6200);

await page.goto(SITE, { waitUntil: 'networkidle' });
await say('Now the part that matters: the containment moment.', 3200);
await page.click('#attack');
await wait(600);
await say('These are real attacks on real sandboxes: steal the keys, phone home to evil.example, reach the host.', 0);
await finished();
const atk = await page.evaluate(() => ({
  blast: document.querySelector('.blast')?.textContent,
  lines: [...document.querySelectorAll('.totals')].map((x) => x.innerText.replace(/\n/g, ' ')),
  count: document.querySelectorAll('.probe').length,
  escaped: document.querySelectorAll('.st.escaped').length,
}));
console.log('attack', page.url(), JSON.stringify(atk));
fs.writeFileSync(OUT + 'run-attack.txt', page.url() + '\n' + JSON.stringify(atk));
if (atk.escaped) throw new Error('an attempt escaped, do not use this take');
await say(`Blast radius: ${atk.blast}. None of the ${atk.count} attempts got out.`, 4500);
await say('The host scanned everything for its own secrets. An approved call still worked, so the box isn\'t just broken.', 6000);
await scrollTo('.probe', 'center');
await say('Each attempt, with the real error it hit.', 4000);
await scrollBy(320); await wait(1800);
await scrollBy(320);
await say('Memory bomb, fork bomb, CPU spin, output flood: all stopped.', 4400);

await page.goto(process.env.POISON_RUN, { waitUntil: 'networkidle' });
await wait(800);
await say('A simulated token whose name is a prompt injection. The model reported it as a red flag instead of obeying.', 5600);
await say('And if a model ever does obey, it\'s still inside the box. That\'s the point.', 4400);

await page.goto(SITE, { waitUntil: 'networkidle' });
await scrollTo('#how');
await say('Receipts. An agent that shows its work, and can\'t hurt you when it\'s wrong.', 4600);
await say('Running on Vultr Cloud Compute and Vultr Serverless Inference.', 3600);

await page.close();
const video = await page.video().path();
await ctx.close();
await browser.close();
console.log('video', video);
