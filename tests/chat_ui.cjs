// Exercise the production renderer and button handlers with a minimal DOM.
// No browser, provider, scan, network or additional npm packages are needed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../app/ui/static/app.js'), 'utf8');
const cards = [], sent = [];
function node(tag, text, cls) {
  return {tag, textContent:text || '', className:cls, children:[],
    append(...items) {this.children.push(...items);},
    setAttribute(key, value) {this[key] = value;}};
}
function flatten(n) {return [n, ...n.children.flatMap(flatten)];}
const context = vm.createContext({node, chatEntry:(_label, text) => {
  const card = node('article', text); cards.push(card); return card;
}, chatFindings:[{id:'high-1', title:'Pattern', severity:'high'}],
status:value => value, findingLink:(_run, id) => node('button', id),
sendChat:(payload, label) => sent.push({payload, label}),
selectChatContext:async (id) => assert.equal(id, 'original-run'), fail:error => {throw error;}});
vm.runInContext(source.slice(source.indexOf('function chatReply('), source.indexOf('function handleChatData(')), context);
const answer = {summary:'Полезная первая часть <script>unsafe()</script>', answer:'',
  confirmed_points:['Observed pattern'], assumptions_or_manual_checks:['Check input'],
  remediation_priorities:['Fix after validation'], truncated:true, notice:'Ответ сокращён',
  referenced_finding_ids:[], caveats:[], suggested_next_questions:[],
  finding_facts:[{id:'high-1', title:'Pattern', severity:'high', source:'SAST'}],
  enrichment_status:'completed'};
async function main() {
  const card = context.chatReply({run_id:'original-run', finding_id:null, question:'Все findings?', analysis:answer});
  const items = flatten(card);
  assert(items.some(n => n.textContent === answer.summary && n.tag === 'p'));
  assert(!items.some(n => n.tag === 'script'));
  assert(items.some(n => n.className === 'chat-warning' && n.role === 'status'));
  for (const heading of ['Подтверждено сканерами', 'Требует ручной проверки', 'Почему это важно / приоритеты исправления']) {
    assert(items.some(n => n.tag === 'h3' && n.textContent === heading));
  }
  for (const [label, mode] of [['Продолжить','continue'], ['Сжать ответ','shorten'],
    ['Только подтверждённые факты','confirmed'], ['Только то, что требует ручной проверки','manual']]) {
    const button = items.find(n => n.tag === 'button' && n.textContent === label);
    assert(button); button.onclick();
    const {payload} = sent.at(-1);
    assert.equal(payload.follow_up, mode);
    assert.equal(payload.run_id, 'original-run');
    assert.equal(payload.finding_id, null);
    assert.equal(payload.action.intent, 'ANALYZE_RUN');
    assert(payload.previous_answer.includes('Полезная первая часть'));
  }
  await items.find(n => n.textContent === 'Разобрать по одной находке').onclick();
  flatten(cards.at(-1)).find(n => n.tag === 'button').onclick();
  assert.equal(sent.at(-1).payload.finding_id, 'high-1');
  assert.equal(sent.at(-1).payload.action.intent, 'EXPLAIN_FINDING');
  const complete = context.chatReply({analysis:{...answer, truncated:false}});
  assert(!flatten(complete).some(n => n.textContent === 'Продолжить'));
  // Exercise sendChat with different currently-selected finding: explicit context wins.
  const requests = [];
  context.$ = id => ({value:id === 'chat-run' ? 'original-run' : 'other-finding', querySelector:() => ({})});
  context.api = async (url, payload) => {requests.push({url, payload}); return {};};
  context.handleChatData = () => {};
  context.displayLLM = () => {};
  context.chatBusy = false;
  vm.runInContext(source.slice(source.indexOf('async function sendChat('), source.indexOf('document.querySelectorAll("[data-intent]"')), context);
  await context.sendChat({run_id:'original-run', finding_id:null, follow_up:'continue'}, 'continue');
  assert.equal(requests[0].payload.finding_id, null);
  console.log('Chat DOM rendering and all follow-up actions passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
