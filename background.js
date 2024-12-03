import publicSuffixList from './libs/publicsuffixlist.js';
import punycode from './libs/punycode.es6.js';

publicSuffixList.enableWASM();


fetch('./data/public_suffix_list.dat')
    .then(response => response.text())
    .then(data => {
        publicSuffixList.parse(data, punycode.toASCII);
    })
    .catch(error => {
        console.error('Error fetching public_suffix_list.dat:', error);
    });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.req === 'geteTLDp1') {
         chrome.tabs.query({currentWindow: true, active: true})
        .then(([tab]) => {
            let eTLDp1 = publicSuffixList.getDomain(new URL(tab.url).hostname);
            sendResponse({res: eTLDp1});
        }, console.error);
    }
    return true;
});


chrome.runtime.onInstalled.addListener(function(details){
    if(details.reason == "install"){
        chrome.tabs.create({active: true, url: "setup.html"});
    }
});