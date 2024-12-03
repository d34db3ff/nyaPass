
let passwordElm = document.getElementById("password");
let eTLDElm = document.getElementById("eTLD");

chrome.runtime.sendMessage({req: "geteTLDp1"}, (response) => {
    if(response.res !== ''){
        eTLDElm.textContent = response.res;
    }else{
        passwordElm.textContent = "Cannot get eTLD for the current tab.";
        passwordElm.disabled = true;
    }
});


passwordElm.addEventListener("click", (e) => {
    e.currentTarget.setAttribute("aria-busy", true);
    
    if(eTLDElm.textContent){
        let eTLD = new TextEncoder().encode(eTLDElm.textContent);
        let challenge = window.crypto.getRandomValues(new Uint8Array(16)).buffer;
        navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                timeout: 60000,
                rpId: "nya.Pass",
                hints: ["security-key"],
            		userVerification: "discouraged",
                extensions: {prf: {eval: {first: eTLD}}},
            }
        })
        .then(authenticatorRes => {
            let clientData = JSON.parse(String.fromCharCode(...new Uint8Array(authenticatorRes.response.clientDataJSON)));
            
            //quick hack for base64/base64url conversion
            let oriChallenge = btoa(String.fromCharCode(...new Uint8Array(challenge))).replace(/=/g, '');
            let rcvChallenge = clientData.challenge.replace(/-/g, '+').replace(/_/g, '/');
            if(oriChallenge !== rcvChallenge){
                throw new Error("Challenge mismatch.");
            }
            
            let prfRes = new Uint8Array(authenticatorRes.getClientExtensionResults().prf.results.first);

            // lossy base58-like output without introducing a new dependency
            let applicationKey = btoa(String.fromCharCode(...prfRes)).replace(/[=\+\/oOIl]/g, '');

            applicationKey = applicationKey.slice(0, 4)
            +'-' + applicationKey.slice(4, 8)
            +'-' + applicationKey.slice(8, 12)
            +'-' + applicationKey.slice(12, 16); 

            passwordElm.parentElement.textContent = applicationKey;
            passwordElm.removeAttribute("aria-busy");
            passwordElm.disabled = true;


        })
        .catch(console.error);
    }
});
