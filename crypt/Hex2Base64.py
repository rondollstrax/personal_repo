import base64, urllib2
def hex_string_to_b64(string):
    hexlist = hex_string_to_hexnumlist(string)
    translated_string = ''
    for hex_char in hexlist:
        translated_string += chr(int(hex_char, 16))
    return base64.b64encode(translated_string)

def hex_string_to_ascii(string):
    return base64.b64decode(hex_string_to_b64(string))

def xor_ice(string):
    xorkeylist = [hex(ord('I'))[2:], hex(ord('C'))[2:], hex(ord('E'))[2:]]
    hexstring = hexify_string(string)
    xorkey = ''
    for i in range(0, len(hexstring), 2):
        xorkey += xorkeylist[i/2 % 3]
    return xor_hexstring(hexstring, xorkey)

def hexify_string(string):
    lst = [c for c in string]
    for item in range(0, len(lst)):
        lst[item] = str(hex(ord(lst[item])))
    return ''.join(lst).replace('0x', '')

def hex_string_to_hexnumlist(string):
    splist = [c for c in string]
    jlist = [x + y for x, y in zip(splist[::2], splist[1::2])]
    while '0x' in jlist:
        jlist.remove('0x')
    hexlist = ['0x' + item for item in jlist]
    return hexlist

def xor_hexstring(string1, string2):
    hexlist1 = hex_string_to_hexnumlist(string1)
    hexlist2 = hex_string_to_hexnumlist(string2)
    result = [hex(int(hexlist1[item], 16) ^ int(hexlist2[item], 16)) for item in range(len(hexlist1))]
    return ''.join(result).replace('0x', '')

def single_char_xor(string1):
    org = []
    for item in range(1, 256):
        item = hex(item)[2:] * (int(len(string1)/(len(hex(item))-2))) 
        org.append(hex_string_to_ascii(xor_hexstring(string1, item)))
    asciitable = [i for i in range(32, 127)]
    for item in org[:]:
        if ' ' not in item:
            org.remove(item)
            continue
        for char in item:
            if ord(char) not in asciitable:
                org.remove(item)
                break
    return '\n'.join(org)

def detect_xor_hex():
    url = "http://cryptopals.com/static/challenge-data/4.txt"
    dataobj = urllib2.urlopen(url)
    hexlistNL = dataobj.readlines()
    hexlist = map(lambda x: x.replace('\n', ''), hexlistNL)
    print map(single_char_xor, hexlist)


if __name__ == '__main__':
    print xor_ice("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
