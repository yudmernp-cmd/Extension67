import {clean} from './sanitizer.js';
export async function saveReport(report){const data=await chrome.storage.local.get('history');const items=[clean(report),...(data.history||[])].slice(0,5);while(JSON.stringify(items).length>1500000&&items.length>1)items.pop();await chrome.storage.local.set({history:items});}
export async function history(){return (await chrome.storage.local.get('history')).history||[];}
