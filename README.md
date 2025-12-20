[Try it on chrome](https://chromewebstore.google.com/detail/nakacffbdjnnmgcdcfnedknbpdophhop/)

https://github.com/user-attachments/assets/62d7898b-dcdd-4868-9e9d-ed2c1a49be00

========

This is a minimalist Password Manager which aims to remove the complexity of syncing and storing password states.

It could work without an Internet connection (in case you live in North Korea).

And, perhaps more importantly, it doesn't require the user to know a master password/phrase/knowledge/etc, the passkey is the only credential a user will need to prove its identity, even the website itself does not support WebAuthn natively.

Unique Application Passwords are derived from the passkey locally, in a consistent and reproducible way.

It turns the FIDO key into a unique set of passwords for websites which do not yet support WebAuthn.

Given the simplicity of this project and the fact that I'm not a frontend developer, I'm not using a proper build system/frontend framework, this repository is the final distribution per se and could be installed without building it first.

# How does this thing work?
$Password = PRF(key, Origin)$

As simple as that.

We use the prf extension from the WebAuthn Standard as the PRF to derive the Application passwords. This extension generates a random secret which is used as the key for the PRF and is kept secret in the physical passkey. 

Note: For compatibility reasons, we use eTLD+1 as the origin of the website in question. For example, www.example.com and whatever.www1.example.com are considered to share the same origin (example.com).

# Security Considerations

## Cross-origin Iframes
TBD
## Hash Length Extension
According to [CTAP](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension), the authenticator uses SHA256-HMAC internally. Although SHA256 itself is vulnerable to Hash Length Extension attack, that does not apply to SHA256-HMAC.

# Known Limitations

## Mandatory User Verification
Unfortunately, we cannot skip user verification (thus have to enter the PIN) every time we use nyaPass to get a password from the passkey.
This annoying restriction stems from the WebAuthn standard.

> when implementing on top of hmac-secret, that PRF MUST be the one used for when user verification is performed. This overrides the UserVerificationRequirement if necessary.



## Cross-Browser Support

To be able to access the same PRF key, our web extension needs to keep the same extension ID.

However, this makes it impossible for the extension to use the same PRF across different Browser Engines, as the extension ID (which implies the RpId used to access our PRF key) would change.

Fortunately, this rule has been relaxed for Chrome 122+. More details on this can be found below.

Please note that Firefox and Safari currently do not support this feature.

## Password Rotation
You can rotate ALL the passwords by replacing the secret stored in the passkey.
An arguably better alternative might be to store a nounce/counter state for each website as a blob in the passkey.

## Supported Browsers
Chrome 122+ Only

The extension of support to other browsers in the future will depend on the availability of [something like this](https://chromiumdash.appspot.com/commit/cfea6b18ede2a8fe0d7ea32e6bba967a7f2de6f8).

## Supported Authenticators 
The Current WebAuthn PRF implementations heavily rely on the CTAP2 HMAC-Secret extension.

At present, only CTAP2 Authenticators that implement the HMAC-Secret extension are supported. These are typically physical and external devices, such as Yubikeys.

However, Platform Authenticators, which are embedded in the laptops or phones, are not currently supported.

Platform authenticators without CTAP2 might support this feature in the future, as per [the standard](https://w3c.github.io/webauthn/#prf-extension)


# Acronym
"nya" stands for "not yet another"

# Todo
- PWA if possible - nope
- native support for other platforms 
