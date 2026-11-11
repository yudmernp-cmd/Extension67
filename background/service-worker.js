// No persistent collection, timers, network listeners or external services.
chrome.runtime.onInstalled.addListener(()=>chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}));
