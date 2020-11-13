import $ from 'jquery';

import { equals } from './crypto';
import { parse, stringify } from './krjson';
import { Message, Request, RequestType, UserActionType } from './messages';

$(document).ready(async () => {

    $('.extension-version').text(chrome.runtime.getManifest().version);
    const pair = document.getElementById('pairScreen');

    const userActionBoard = document.getElementById('userActionBoard');
    const yesButton = document.getElementById('ua_yesButton');
    const noButton = document.getElementById('ua_noButton');
    const textFieldForm = document.getElementById('ua_textFieldForm');

    userActionBoard.classList.add('remove');
    yesButton.classList.add('remove');
    noButton.classList.add('remove');
    textFieldForm.classList.add('remove');

    onPopupOpen();
    pollState();

    $('#unpairButton').click(async () => {
        pair.classList.remove('remove');

        chrome.runtime.sendMessage(await stringify(
            Message.newRequest(new Request(RequestType.unpair)),
        ));
    });
});

async function onPopupOpen() {
    const m = new Message();
    m.request = new Request(RequestType.refreshPopup);
    chrome.runtime.sendMessage(await stringify(m));
}

async function pollState() {
    const poll = async () => {
        if (!document.hasFocus()) {
            return;
        }
        const m = new Message();
        m.request = new Request(RequestType.getState);
        chrome.runtime.sendMessage(await stringify(m));
    };
    await poll();
    setInterval(poll, 1000);
}

let isFirstTimeOpen = true;
let lastQrCode = null;

chrome.runtime.onMessage.addListener(async (msg, sender) => {
    const launch = document.getElementById('launch');
    const pair = document.getElementById('pairScreen');
    const accounts = document.getElementById('accounts');

    const m = await parse(Message, msg);

    if (m.response) {
        const r = m.response;
        if (r.paired) {
            launch.classList.add('remove');
            pair.classList.add('remove');
            accounts.classList.remove('remove');
            if (r.u2fAccounts) {
                for (const acctId of r.u2fAccounts) {
                    const acctElem = document.getElementById(acctId);

                    if (acctElem != null) {
                        acctElem.classList.remove('unsecured');
                        acctElem.classList.add('secured');
                    }
                }
            }

        } else if (r.qr) {
            accounts.classList.add('remove');

            if (isFirstTimeOpen) {
                launch.classList.add('launchopen');

                setTimeout(async function() {
                    launch.classList.add('remove');
                    pair.classList.remove('remove');
                    isFirstTimeOpen = false;
                }, 600);
            } else {
                launch.classList.add('remove');
                pair.classList.remove('remove');
            }

            if (lastQrCode == null || (await equals(lastQrCode, r.qr.pk)) === false) {
                lastQrCode = r.qr.pk;
                $('#pairingQR').html(await r.qr.render());
            }
        }
        if (r.phoneName) {
            $('.tokenName').text(r.phoneName);
        }
    } else if (m.userAction) {
        const userActionBoard = document.getElementById('userActionBoard');
        const yesButton = document.getElementById('ua_yesButton');
        const noButton = document.getElementById('ua_noButton');
        const textFieldForm = document.getElementById('ua_textFieldForm');

        userActionBoard.classList.remove('remove');

        $('#userActionMessage').text(m.userAction.displayText);

        const hideActionBoard = () => {
            // Hide everything
            userActionBoard.classList.add('remove');
            yesButton.classList.add('remove');
            noButton.classList.add('remove');
            textFieldForm.classList.add('remove');
        };

        var ret: Promise<any>;
        switch (m.userAction.actionType) {
                case UserActionType.yes_no: {
                    // Show the buttons
                    yesButton.classList.remove('remove');
                    noButton.classList.remove('remove');

                    ret = new Promise((resolve) => {
                        $('#ua_yesButton').click(() => { hideActionBoard(); resolve({response: true}); });
                        $('#ua_noButton').click(() => { hideActionBoard(); resolve({response: false}); });            
                    });
                    break;
                }
                case UserActionType.text_field: {
                    // Show the text field
                    textFieldForm.classList.remove('remove');
                    ret = new Promise((resolve) => {
                        $('#ua_textFieldSubmit').click(() => { hideActionBoard(); 
                                                               resolve({response: (<HTMLInputElement>document.getElementById('ua_textField')).value}); });
                    });
                    break;
                }
        }

        return ret;
    }
});
