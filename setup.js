document.getElementById("register").addEventListener("click", () => {
    let challenge = window.crypto.getRandomValues(new Uint8Array(16)).buffer;
    navigator.credentials.create({
        publicKey: {
            rp: {name: "nyaPass", id: "nya.Pass"},
            user: {
                id: new Uint8Array(16),
                name: "nyaPass",
                displayName: "nyaPass"
            },
            pubKeyCredParams: [{type: "public-key", alg: -8}],
            timeout: 60000,
            authenticatorSelection: {
                authenticatorAttachment: "cross-platform",
                residentKey: "required",
                userVerification: "discouraged"
            },
            hints: ["security-key"],

            extensions: {prf: {}},
    
            challenge: challenge
        }
    })
    .then((authenticatorRes) => {
        let clientData = JSON.parse(String.fromCharCode(...new Uint8Array(authenticatorRes.response.clientDataJSON)));

        //quick hack for base64/base64url conversion
        let oriChallenge = btoa(String.fromCharCode(...new Uint8Array(challenge))).replace(/=/g, '');
        let rcvChallenge = clientData.challenge.replace(/-/g, '+').replace(/_/g, '/');
        if(oriChallenge !== rcvChallenge){
            throw new Error("Challenge mismatch.");
        }
        console.log(authenticatorRes.toJSON());
    })
    .catch(console.error)
    .finally(() => window.close());
});
