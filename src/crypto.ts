import sodium, {Uint8ArrayOutputFormat} from 'libsodium-wrappers-sumo';

//  Non-throwing wrapper around sodium's constant-time compare
export async function equals(a: Uint8Array, b: Uint8Array): Promise<boolean> {
    await sodium.ready;
    if (a.constructor !== Uint8Array || b.constructor !== Uint8Array) {
        return false;
    }
    if (a.length !== b.length) {
        return false;
    }
    return 0 === sodium.compare(a, b);
}

export async function to_base64(d: string | Uint8Array) {
    await sodium.ready;
    return sodium.to_base64(d, sodium.base64_variants.ORIGINAL);
}

//  https://github.com/mafintosh/base64-to-uint8array/blob/master/index.js
export function from_base64(s: string) {
    return new Uint8Array(atob(s).split('').map((c) => c.charCodeAt(0)));
}

export async function to_base64_url(d: string | Uint8Array) {
    await sodium.ready;
    return sodium.to_base64(d, sodium.base64_variants.URLSAFE);
}

export async function from_base64_url(s: string) {
    await sodium.ready;
    return sodium.from_base64(s, sodium.base64_variants.URLSAFE);
}

export async function to_base64_url_nopad(d: string | Uint8Array) {
    await sodium.ready;
    return sodium.to_base64(d, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export async function from_base64_url_nopad(s: string) {
    await sodium.ready;
    return sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export async function crypto_hash_sha256(d: string | Uint8Array) {
    await sodium.ready;
    return sodium.crypto_hash_sha256(d);
}

export async function randombytes_buf(length: number) {
    await sodium.ready;
    return sodium.randombytes_buf(length);
}

export async function crypto_box_keypair() {
    await sodium.ready;
    return sodium.crypto_box_keypair('uint8array');
}

export async function crypto_box_seal_open(
                                            ciphertext: string | Uint8Array | undefined,
                                            publicKey: Uint8Array,
                                            privateKey: Uint8Array,
                                            outputFormat?: sodium.Uint8ArrayOutputFormat | null,
                                        ): Promise<Uint8Array> {
    await sodium.ready;
    return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey, outputFormat);
}

export async function crypto_box_open_easy(
                                            ciphertext: string | Uint8Array | undefined,
                                            nonce: Uint8Array,
                                            publicKey: Uint8Array,
                                            privateKey: Uint8Array,
                                            outputFormat?: sodium.Uint8ArrayOutputFormat | null,
                                        ): Promise<Uint8Array> {
    await sodium.ready;
    return sodium.crypto_box_open_easy(ciphertext, nonce, publicKey, privateKey, outputFormat);
}

export async function crypto_box_easy(
                                        message: string | Uint8Array | undefined,
                                        nonce: Uint8Array,
                                        publicKey: Uint8Array,
                                        privateKey: Uint8Array,
                                        outputFormat?: Uint8ArrayOutputFormat | null,
                                    ): Promise<Uint8Array> {
    await sodium.ready;
    return sodium.crypto_box_easy(message, nonce, publicKey, privateKey, outputFormat);
}

export async function signature_to_ASN1(signature: Uint8Array): Promise<Uint8Array> {
    // TODO: Could be made more efficient by avoiding all of the copies

    // From: https://stackoverflow.com/questions/39554165/ecdsa-signatures-between-node-js-and-webcrypto-appear-to-be-incompatible
    // Modified to work directly in `Uint8Array`
    let r = signature.slice(0, 32);
    let s = signature.slice(32);
    let rPre = true;
    let sPre = true;

    while(r[0] === 0x00) {
        r = r.slice(2);
        rPre = false;
    }    

    if (rPre && r[0] > 127) {
        r = new Uint8Array([0, ...r]);
    }

    while(s[0] === 0x00) {
        s = s.slice(2);
        sPre = false;
    }

    if(sPre && s[0] > 127) {
        s = new Uint8Array([0, ...s]);
    }

    const payload = new Uint8Array([0x02, r.byteLength, ...r, 0x02, s.byteLength, ...s]);
    const der = new Uint8Array([0x30, payload.byteLength, ...payload]);

    return der;
}
