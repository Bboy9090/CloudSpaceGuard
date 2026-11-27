'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('web/index.html', 'utf8');
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
if (scripts.length === 0) throw new Error('No inline dashboard scripts found');
scripts.forEach((match, index) => new vm.Script(match[1], { filename: `dashboard-inline-${index}.js` }));
console.log(`Parsed ${scripts.length} inline dashboard scripts`);
