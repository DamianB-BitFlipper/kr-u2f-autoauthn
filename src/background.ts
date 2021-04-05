import * as CBOR from 'cbor';

import { Browser, browser as detectBrowser } from './browser';
import { crypto_hash_sha256, from_base64_url_nopad, to_base64_url_nopad, signature_to_ASN1 } from './crypto';
import { EnclaveClient, PopupRequest } from './enclave_client';
import { RequestTypes, ResponseTypes } from './enums';
import { parse, stringify, webauthnParse, webauthnStringify } from './krjson';
import { Message, RequestType, Toast, UserAction } from './messages';
import { BAD_APPID, checkIsRegistrableDomainSuffix, fetchAppIdUrl, verifyU2fAppId } from './origin-checker';
import * as protocol from './protocol';
import { addPresenceAndCounter, client, makeRegisterData } from './u2f';
import { getDomainFromOrigin, getOriginFromUrl } from './url';
import { createAuthenticatorDataWithAttestation, createAuthenticatorDataWithoutAttestation } from './webauthn';
import { get, set } from './storage';

async function onRequest(msg, sender) {
    if (msg.type) {
        if (msg.type === RequestTypes.REGISTER_U2F) {
            const sendResponse = getResponseSender(ResponseTypes.REGISTER_U2F, msg.requestId, sender);
            handle_u2f_register(msg, sender).then(sendResponse)
                                            .catch((e) => { console.error(e); sendResponse({ fallback: true }); });
            return;
        } else if (msg.type === RequestTypes.REGISTER_WEBAUTHN) {
            const sendResponse = getResponseSender(ResponseTypes.REGISTER_WEBAUTHN, msg.requestId, sender);
            handle_webauthn_register(msg, sender).then(sendResponse)
                                                 .catch((e) => { console.error(e); sendResponse({ errorCode: -1 }); });
            return;
        } else if (msg.type === RequestTypes.SIGN_U2F) {
            const sendResponse = getResponseSender(ResponseTypes.SIGN_U2F, msg.requestId, sender);
            handle_u2f_sign(msg, sender).then(sendResponse)
                                        .catch((e) => { console.error(e); sendResponse({ fallback: true }); });
            return;
        } else if (msg.type === RequestTypes.SIGN_WEBAUTHN) {
            const sendResponse = getResponseSender(ResponseTypes.SIGN_WEBAUTHN, msg.requestId, sender);
            handle_webauthn_sign(msg, sender).then(sendResponse)
                                            .catch((e) => { console.error(e); sendResponse({ errorCode: -1 }); });
            return;
        }
    }
    if (typeof(msg) === 'string') {
        msg = await parse(Message, msg);
    }
    return onMessage(msg);
}

async function onMessage(m: Message) {
    const c = await client;
    if (m.request) {
        switch (m.request.ty) {
            case RequestType.getState: {
                sendFullStateToPopup(c);
                break;
            }
            case RequestType.refreshPopup: {
                await c.refreshPopup();
                break;
            }
            case RequestType.unpair: {
                await c.unpair(true);
                sendFullStateToPopup(c);
                break;
            }
        }
    }
}

switch (detectBrowser()) {
    case Browser.safari:
        safari.application.addEventListener('message', (evt) => {
            onRequest((evt as any).message, evt.target);
        });
        (safari.extension.globalPage.contentWindow as any).krRequestGlobalPage = onRequest;
        break;
    default:
        chrome.runtime.onMessage.addListener(onRequest);
}

function getFetcher(sender: chrome.runtime.MessageSender) {
    switch (detectBrowser()) {
        case Browser.safari:
            return fetchAppIdUrl;
        case Browser.chrome:
            return fetchAppIdUrl;
        default:
            return function fetch(url: string): Promise<string> {
                return new Promise(function(resolve, reject) {
                    const msg = {
                        type: 'url_fetch',
                        url,
                    };
                    chrome.tabs.sendMessage(sender.tab.id, msg, (response) => {
                        if (response == null) {
                            reject(chrome.runtime.lastError);
                        } else {
                            resolve(String(response));
                        }
                    });
                });
            };
    }
}

function getResponseSender(responseType: string,
                           requestId: number,
                           sender: chrome.runtime.MessageSender | browser.runtime.MessageSender) {
    let responseSent = false;
    return function(responseData: object) {
        if (responseSent) {
            console.warn('Attempting to send multiple responses');
            return;
        }
        responseSent = true;
        const response = {
            data: {
                requestId,
                responseData,
            },
            type: responseType,
        };
        sendIfTabActive(sender, response);
    };
}

async function handle_webauthn_register(msg: any,
                                        sender: chrome.runtime.MessageSender | browser.runtime.MessageSender) {
    const c = await client;

    const options: CredentialCreationOptions = webauthnParse(msg.options);
    const pkOptions = options.publicKey;

    const origin = getOriginFromUrl(sender.url);
    if (pkOptions.rp.id && !checkIsRegistrableDomainSuffix(origin, pkOptions.rp.id)) {
        throw new Error('SecurityError');
    }
    const rpId = pkOptions.rp.id || getDomainFromOrigin(origin);
    if (pkOptions.excludeCredentials) {
        for (const excludeCredential of pkOptions.excludeCredentials) {
            const keyHandle = new Uint8Array(excludeCredential.id as ArrayBuffer);
            if (await c.mapKeyHandleToMatchingAppId(keyHandle, {rpId})) {
                throw new Error('Krypton already registered with this account');
            }
        }
    }

    let foundNistKeyType = false;
    if (pkOptions.pubKeyCredParams) {
        for (const params of pkOptions.pubKeyCredParams) {
            // webauthn.io sets alg to the string '-7', so we accept anything that coerces to -7
            // tslint:disable-next-line:triple-equals
            if (params.alg == -7 && params.type === 'public-key') {
                foundNistKeyType = true;
                break;
            }
        }
        if (!foundNistKeyType) {
            throw new Error('only nistp256 keys supported');
        }
    }

    const clientData: protocol.WebauthnClientData = {
        challenge: await to_base64_url_nopad(new Uint8Array(pkOptions.challenge as any)),
        clientExtensions: {},
        hashAlgorithm: 'SHA-256',
        origin: origin,
        type: 'webauthn.create',
    };
    const clientDataJSON = JSON.stringify(clientData);
    const clientDataB64 = await to_base64_url_nopad(clientDataJSON);

    // TODO: The 'challenge is not used anywhere'
    const challenge = await crypto_hash_sha256(clientDataJSON);

    //
    // TODO: Move this to an enrollU2f-like function
    //

    // Extract the x/y-coords of this elliptic curve public key
    const public_key_json = await get('my_pubkey');
    const public_key_encoded = JSON.parse(public_key_json);
    const pk_x = await from_base64_url_nopad(public_key_encoded.x);
    const pk_y = await from_base64_url_nopad(public_key_encoded.y);

    // Extract the signature counter
    const sign_count_json = await get('my_sign_count');
    const sign_count = JSON.parse(sign_count_json);

    // Create a valid `key_handle`
    // ADDED const key_handle = await c.create_key_handle(rpId);
    // ADDED This is a key handle for deterministic key generation
    const key_handle = new Uint8Array([44, 229, 200, 223, 23, 226, 46, 242, 15, 211, 131, 3, 253, 45, 153, 152, 189, 69, 78, 90, 167, 8, 236, 12, 129, 12, 1, 13, 84, 3, 66, 115, 85, 3, 34, 220, 119, 214, 26, 235, 132, 81, 225, 45, 9, 227, 208, 179, 32, 176, 24, 201, 44, 182, 52, 80, 0, 173, 75, 220, 192, 112, 254, 101, 83, 234, 79, 173, 107, 145, 97, 18, 168, 230, 129, 214, 97, 70, 173, 215]);

    const u2fRegisterResponse: protocol.U2FRegisterResponse = {
        public_key: new Uint8Array([...pk_x, ...pk_y]),
        counter: sign_count,
        signature: new Uint8Array([]), // Omit
        attestation_certificate: new Uint8Array([]), // Omit
        key_handle: key_handle,
        error: '',
    };

    //
    // TODO: Move this to an enrollU2f-like function
    //

    const authenticatorData = await createAuthenticatorDataWithAttestation(rpId,
                                                                           u2fRegisterResponse.counter,
                                                                           u2fRegisterResponse.key_handle,
                                                                           u2fRegisterResponse.public_key);

    let attestationObject: ArrayBuffer;
    if (pkOptions.attestation == null || pkOptions.attestation === 'none') {
        attestationObject = CBOR.encodeCanonical({
            attStmt: {},
            authData: new Buffer(authenticatorData.buffer),
            fmt: 'none',
        }).buffer;
    } else {
        attestationObject = CBOR.encodeCanonical({
            attStmt: {
                sig: new Buffer(u2fRegisterResponse.signature.buffer),
                x5c: [new Buffer(u2fRegisterResponse.attestation_certificate.buffer)],
            },
            authData: new Buffer(authenticatorData.buffer),
            fmt: 'fido-u2f',
        }).buffer;
    }

    const credential: PublicKeyCredential = {
        id: await to_base64_url_nopad(u2fRegisterResponse.key_handle),
        rawId: u2fRegisterResponse.key_handle.buffer,
        response: {
            attestationObject,
            clientDataJSON: (await from_base64_url_nopad(clientDataB64)).buffer,
        },
        type: 'public-key',
    };

    const authenticatedResponseData = {
        credential: webauthnStringify(credential),
    };
    return authenticatedResponseData;
}

async function handle_u2f_register(msg: any, sender: chrome.runtime.MessageSender | browser.runtime.MessageSender) {
    const fetcher = getFetcher(sender);
    const origin = getOriginFromUrl(sender.url);
    const appId = msg.appId
        || ((msg.registerRequests && msg.registerRequests.length > 0) ? msg.registerRequests[0].appId : null)
        || origin;

    try {
        await verifyU2fAppId(origin, appId, fetcher);
    } catch (err) {
        console.error(err);
        return {errorCode: BAD_APPID};
    }

    const c = await client;

    if (!c.pairing.isPaired()) {
        throw new Error('Krypton not paired');
    }
    const existingKeyHandles: string[] = [];
    if (msg.registeredKeys) {
        for (const registeredKey of msg.registeredKeys) {
            existingKeyHandles.push(registeredKey.keyHandle);
        }
    }
    if (msg.signRequests) {
        for (const signRequest of msg.signRequests) {
            existingKeyHandles.push(signRequest.keyHandle);
        }
    }
    for (const existingKeyHandle of existingKeyHandles) {
        try {
            const keyHandle = await from_base64_url_nopad(existingKeyHandle);
            if (await c.mapKeyHandleToMatchingAppId(keyHandle, { appId })) {
                //  already registered
                return { fallback: true };
            }
        } catch (e) {
            console.error(e);
        }
    }

    let serverChallenge: string;
    let clientData: string;

    //  TODO: detect U2F_V2/V1 requests
    serverChallenge = msg.registerRequests[0].challenge;
    clientData = JSON.stringify({
        challenge: serverChallenge,
        cid_pubkey: 'unused',
        origin,
        typ: 'navigator.id.finishEnrollment',
    });

    const challenge = await crypto_hash_sha256(clientData);

    const response = await c.enrollU2f({
        app_id: appId,
        challenge,
    });
    if (!response.u2f_register_response) {
        throw new Error('no u2f_register_response');
    }
    if (response.u2f_register_response.error) {
        throw response.u2f_register_response.error;
    }

    const authenticatedResponseData = {
        clientData: await to_base64_url_nopad(clientData),
        keyHandle: await to_base64_url_nopad(response.u2f_register_response.key_handle),
        registrationData: await to_base64_url_nopad(makeRegisterData(response.u2f_register_response)),
        version: 'U2F_V2',
    };
    return authenticatedResponseData;
}

// TODO: Move function to more appropriate place, like enclave_client.ts
//
// This function is "trusted" since it performs the role of the hardware authenticator
async function authenticatorGetAssertion(rpId: string, clientData: protocol.WebauthnClientData): Promise<Uint8Array[]> {
    const clientDataJSON = JSON.stringify(clientData);
    const challenge = await crypto_hash_sha256(clientDataJSON);

    const extensions = clientData.clientExtensions;

    // TODO: What should be done on unrecognized extension? ignore or error?
    //
    // Handle `extensions` behavior for 'txAuthSimple'
    if (extensions && extensions.hasOwnProperty('txAuthSimple')) {
        const c = await client;

        // Print the transaction authorization text
        console.warn('Authentication message: ' + extensions.txAuthSimple);

        let userResponse: boolean | undefined = undefined;
        function __delay__(ms: number) {
            return new Promise( resolve => setTimeout(resolve, ms) );
        }

        async function waitForUser(){
            while (userResponse === undefined) {
                // Wait 50 milliseconds then retry
                await __delay__(50);
            }
        }

        const userAction = new UserAction();
        userAction.displayText = extensions.txAuthSimple;

        const popupReq = new PopupRequest();
        popupReq.msg = Message.newUserAction(userAction);
        popupReq.responseHandler = (resp: any) => {
            userResponse = resp.response;
        };
        popupReq.errorHandler = (error?: any) => {
            if (error != undefined) {
                console.error('PopupRequest errorHandler: ' + error);
            }
            userResponse = false;
        };

        // TODO: Have an ID returned such that the popupReq can be dequeued if
        // the request times out below
        c.enqueuePopupRequest(popupReq);

        // Issue the error handler to reject after no response from the user for 30 seconds
        const errorTimeout = setTimeout(popupReq.errorHandler, 30 * 1000);

        // Wait for the user's response
        await waitForUser();

        // Clear the timeout after the user responded or timeout fired
        clearTimeout(errorTimeout);

        console.warn('Value of userResponse: ' + userResponse);
        if (!userResponse) {
            throw new Error('User declined transaction authentication.');
        }
    }

    // Extract the x/y-coords of this elliptic curve public key
    const public_key_json = await get('my_pubkey');
    const public_key_encoded = JSON.parse(public_key_json);
    const pk_x = await from_base64_url_nopad(public_key_encoded.x);
    const pk_y = await from_base64_url_nopad(public_key_encoded.y);

    // Update the signature counter
    const sign_count_json = await get('my_sign_count');
    const sign_count = JSON.parse(sign_count_json);

    const new_sign_count = sign_count + 1;
    const new_sign_count_json = JSON.stringify(new_sign_count);
    await set('my_sign_count', new_sign_count_json);

    const u2fSignResponse: protocol.U2FAuthenticateResponse = {
        counter: new_sign_count,
        signature: null, // To be filled in later
        public_key: new Uint8Array([...pk_x, ...pk_y]),
        error: '',
    };

    const authenticatorData = await createAuthenticatorDataWithoutAttestation(rpId, u2fSignResponse.counter);

    const to_sign_data = new Uint8Array(authenticatorData.byteLength + 32);
    to_sign_data.set(authenticatorData, 0);
    to_sign_data.set(challenge, authenticatorData.byteLength);

    // Extract the private key as a `CryptoKey` object
    const private_key_json = await get('my_privkey');
    const private_key_encoded = JSON.parse(private_key_json);

    const private_key = await window.crypto.subtle.importKey(
        'jwk',
        private_key_encoded,
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        false,
        ['sign'],
    );

    // Perform the authentication signing
    const signature = await window.crypto.subtle.sign(
        {
            name: 'ECDSA',
            hash: {name: 'SHA-256'},
        },
        private_key,
        to_sign_data.buffer,
    );

    return Promise.resolve([new Uint8Array(signature), authenticatorData]);
}

async function handle_webauthn_sign(msg: any, sender: chrome.runtime.MessageSender) {
    const c = await client;
    const fetcher = getFetcher(sender);

    const pkOptions = webauthnParse(msg.options).publicKey;

    const origin = getOriginFromUrl(sender.url);

    let keyHandle: Uint8Array;
    let matchingAppId: string;
    {
        let appId: string;
        if (pkOptions.extensions && pkOptions.extensions.appid) {
            try {
                await verifyU2fAppId(origin, pkOptions.extensions.appid, fetcher);
                appId = pkOptions.extensions.appid;
            } catch (err) {
                console.error(err);
                return {errorCode: BAD_APPID};
            }
        }
        if (pkOptions.rpId && !checkIsRegistrableDomainSuffix(origin, pkOptions.rpId)) {
            throw new Error('SecurityError');
        }
        const rpId: string = pkOptions.rpId || getDomainFromOrigin(origin);

        for (const credential of pkOptions.allowCredentials) {
            const id = credential.id;
            matchingAppId = await c.mapKeyHandleToMatchingAppId(id, { appId, rpId });
            if (matchingAppId) {
                keyHandle = id;
                break;
            }
        }
    }
    if (!keyHandle) {
        throw new Error('Krypton not registered with this key handle');
    }

    console.warn('pkOptions.extensions: ', pkOptions.extensions);

    const clientData: protocol.WebauthnClientData = {
        challenge: await to_base64_url_nopad(pkOptions.challenge),
        clientExtensions: pkOptions.extensions,
        hashAlgorithm: 'SHA-256',
        origin: origin,
        type: 'webauthn.get',
    };

    const clientDataJSON = JSON.stringify(clientData);
    const clientDataB64 = await to_base64_url_nopad(clientDataJSON);

    // Get the authentication assertion
    const [signature, authenticatorData] = await authenticatorGetAssertion(matchingAppId, clientData);

    const credential: PublicKeyCredential = {
        id: await to_base64_url_nopad(keyHandle),
        rawId: keyHandle.buffer,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: (await from_base64_url_nopad(clientDataB64)).buffer,
            signature: (await signature_to_ASN1(signature)).buffer,
            userHandle: new ArrayBuffer(0),
        },
        type: 'public-key',
    };

    const authenticatedResponseData = {
        credential: webauthnStringify(credential),
    };
    return authenticatedResponseData;
}

async function handle_u2f_sign(msg: any, sender: chrome.runtime.MessageSender) {
    const origin = getOriginFromUrl(sender.url);
    const fetcher = getFetcher(sender);

    const c = await client;
    //  unify both request formats into registeredKeys
    if (msg.signRequests && !msg.registeredKeys) {
        if (msg.signRequests.length === 0) {
            return {};
        }
        const registeredKeys = [];
        for (const signRequest of msg.signRequests) {
            registeredKeys.push({
                appId: signRequest.appId,
                challenge: signRequest.challenge,
                keyHandle: signRequest.keyHandle,
            });
        }
        msg.registeredKeys = registeredKeys;
    }

    let matchingAppId;
    let keyHandle;
    let serverChallenge;
    {
        for (const registeredKey of msg.registeredKeys) {
            const keyHandleBytes = await from_base64_url_nopad(registeredKey.keyHandle);
            const potentialAppId: string = registeredKey.appId || msg.appId || origin;
            const appId = await c.mapKeyHandleToMatchingAppId(keyHandleBytes, {appId: potentialAppId});
            if (appId) {
                keyHandle = keyHandleBytes;
                serverChallenge = registeredKey.challenge || msg.challenge;
                matchingAppId = appId;
                break;
            }
        }
    }
    if (!keyHandle) {
        return {fallback: true};
    }

    try {
        await verifyU2fAppId(origin, matchingAppId, fetcher);
    } catch (err) {
        console.error(err);
        return {errorCode: BAD_APPID};
    }

    const clientData = JSON.stringify({
        challenge: serverChallenge,
        cid_pubkey: 'unused',
        origin: getOriginFromUrl(sender.url),
        typ: 'navigator.id.getAssertion',
    });

    const challenge = await crypto_hash_sha256(clientData);

    const response = await c.signU2f({
        app_id: matchingAppId,
        challenge,
        key_handle: keyHandle,
    });
    if (!response.u2f_authenticate_response) {
        throw new Error('no u2f_authenticate_response');
    }
    if (response.u2f_authenticate_response.error) {
        throw response.u2f_authenticate_response.error;
    }

    const signatureData = await to_base64_url_nopad(
        addPresenceAndCounter(response.u2f_authenticate_response),
    );
    const authenticatedResponseData = {
        clientData: await to_base64_url_nopad(clientData),
        keyHandle: await to_base64_url_nopad(keyHandle),
        signatureData,
    };
    return authenticatedResponseData;
}

function sendStates(c: EnclaveClient) {
    sendFullStateToPopup(c);
}

function sendToPopup(o: any, responseHandler?: (resp: any) => void, errorHandler?: (error: any) => void) {
    switch (detectBrowser()) {
        case Browser.safari:
            const sendFn = (safari.extension.globalPage.contentWindow as any).krSendToPopup;
            if (sendFn) {
                sendFn(o);
            }
            break;
        default:
            const sending = browser.runtime.sendMessage(stringify(o));

            if (responseHandler != undefined || errorHandler !== undefined) {
                sending.then(responseHandler, errorHandler);
            }
    }
}

function sendFullStateToPopup(c: EnclaveClient) {
    const r = c.getState();
    sendToPopup(r);

    // Send over all of the popup requests
    var popupReq: PopupRequest;
    while (popupReq = c.pendingPopupRequests.pop()) {
        sendToPopup(popupReq.msg, popupReq.responseHandler, popupReq.errorHandler);
    }
}

function sendPending(s: string) {
    const t = new Toast();
    t.pending = s;
    const m = Message.newToast(t);
    sendMessageToActiveTab(m);
}

async function sendMessageToActiveTab(m: Message) {
    sendToActiveTab(await stringify(m));
}

async function sendIfTabActive(sender: chrome.runtime.MessageSender | browser.runtime.MessageSender, o: any) {
    switch (detectBrowser()) {
        case Browser.safari:
            (sender as any).page.dispatchMessage(o.type, o);
            return;
        default:
            chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
                if (tabs[0]) {
                    if (tabs[0].id === sender.tab.id) {
                        chrome.tabs.sendMessage(
                            sender.tab.id,
                            o,
                        );
                    } else {
                        console.error('sender tab not active');
                    }
                } else {
                    console.error('no tab active');
                }
            });
    }
}

async function sendToActiveTab(s: string) {
    switch (detectBrowser()) {
        case Browser.safari:
            //  TODO: not yet implemented
            return;
        default:
            chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
                chrome.tabs.sendMessage(
                    tabs[0].id,
                    s,
                );
            });
    }
}

const UA_WINDOWS_CHROME =
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.2526.73 Safari/537.36';
function make_ua_spoofer(userAgent: string, referers?: [string], origins?: [string]) {
    return function user_agent_handler(details) {
        if (referers) {
            if (!details.requestHeaders.some(
                (header) => header.name === 'Referer' && referers.indexOf(header.value) >= 0)) {
                return;
            }
        }

        if (origins) {
            if (!details.requestHeaders.some(
                (header) => header.name === 'Origin' && origins.indexOf(header.value) >= 0)) {
                return;
            }
        }

        for (const header of details.requestHeaders) {
            if (header.name === 'User-Agent') {
                /* tslint:disable */
                header.value = userAgent;
                /* tslint:enable */
                break;
            }
        }

        return { requestHeaders: details.requestHeaders };
    };
}

const fbFilterCatchAll = [
    '*://*.facebook.com/*',
    '*://*.facebook.net/*',
    '*://*.fbcdn.net/*',
];
const fbFilterSpecific = [
    '*://www.facebook.com/checkpoint/?next',
];

switch (detectBrowser()) {
    case Browser.firefox:
        browser.webRequest.onBeforeSendHeaders.addListener(make_ua_spoofer(UA_WINDOWS_CHROME),
                                                   {urls: fbFilterCatchAll},
                                                   ['blocking', 'requestHeaders'],
                                                  );
        break;
    case Browser.edge:
        browser.webRequest.onBeforeSendHeaders.addListener(
            make_ua_spoofer(UA_WINDOWS_CHROME, ['https://www.facebook.com/checkpoint/?next']),
            { urls: fbFilterCatchAll },
            ['blocking', 'requestHeaders'],
        );
        browser.webRequest.onBeforeSendHeaders.addListener(
            make_ua_spoofer(UA_WINDOWS_CHROME, null),
            { urls: fbFilterSpecific },
            ['blocking', 'requestHeaders'],
        );
        break;
}

client.then((c) => { c.onChange = sendStates.bind(null, c); });

declare var Components;

// Create the local public-private keys
async function initPubPrivKeys() {
    console.info('Creating ECDSA public/private keys');

    /* Used to generate new public/private keys
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        true,
        ['sign', 'verify'],
    );

    // Store the public/private keys
    const public_key = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const public_key_json = JSON.stringify(public_key);

    const private_key = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const private_key_json = JSON.stringify(private_key);

    await set('my_pubkey', public_key_json);
    await set('my_privkey', private_key_json);
    */

    // ADDED This is for deterministic key generation
    // Set the public/private keys deterministically
    await set('my_pubkey', '{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"KcNO0p_qaMgb-ataqGGRTfB0_9qaBHryTt62skJzrRA","y":"umamfga7YpXmsdwx-NxAv3WF_qZKZc2o_SrA1lqFY5k"}');
    await set('my_privkey', '{"crv":"P-256","d":"3lZBonO6AZDpfTyOViPPj5hqWqHocbZPGVJGHECEKn0","ext":true,"key_ops":["sign"],"kty":"EC","x":"KcNO0p_qaMgb-ataqGGRTfB0_9qaBHryTt62skJzrRA","y":"umamfga7YpXmsdwx-NxAv3WF_qZKZc2o_SrA1lqFY5k"}');

    // Store the signature counter
    const sign_count_json = JSON.stringify(0);
    await set('my_sign_count', sign_count_json);
}

switch (detectBrowser()) {
    case Browser.safari:
        //  https://stackoverflow.com/questions/9868985/safari-extension-first-run-and-updates
        const storedVersion = safari.extension.settings.version;
        const currentVersion = safari.extension.displayVersion + '.' + safari.extension.bundleVersion;
        if (typeof storedVersion === 'undefined') {
            //  Install
            safari.extension.settings.version = currentVersion;
            safari.extension.toolbarItems[0].showPopover();
        } else if (currentVersion !== storedVersion) {
            //  Update
            console.info('Extension update');
            safari.extension.settings.version = currentVersion;
        }
        break;
    default:
        chrome.runtime.onInstalled.addListener(function(details) {
            if (details.reason === 'install') {
                // On install, initialize the public/private keys
                initPubPrivKeys();

                chrome.tabs.create({ url: '/popup.html' });
            } else if (details.reason === 'update') {
                const thisVersion = chrome.runtime.getManifest().version;
                console.info('Updated from ' + details.previousVersion + ' to ' + thisVersion);
            }
        });
        break;
}
