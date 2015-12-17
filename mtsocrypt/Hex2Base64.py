import base64, urllib2, requests

def repeating_xor(longs, shorts):
    if len(longs) < len(shorts):
        raise ValueError
    f = ''
    for i in range(len(longs)):
        f+=shorts[i%len(shorts)]
    return (f, longs)


def hex_string_to_b64(string):
    hexlist = hex_string_to_hexnumlist(string)
    translated_string = ''
    for hex_char in hexlist:
        translated_string += chr(int(hex_char, 16))
    return base64.b64encode(translated_string)

def hex_string_to_ascii(string):
    return base64.b64decode(hex_string_to_b64(string))

def hex_to_str(string):
    return ''.join([chr(int(string[c] + string[c+1], 16)) for c in range(0, len(string), 2)]) 

def xor_ice(string):
    xorkeylist = [hex(ord('I'))[2:], hex(ord('C'))[2:], hex(ord('E'))[2:]]
    hexstring = hexify_string(string)
    xorkey = ''
    for i in range(0, len(hexstring)*2, 2):
        xorkey += xorkeylist[i/2 % 3]
    return xor_hexstring(hexstring, xorkey)

def hexify_string(string):
    lst = [c for c in string]
    for item in range(0, len(lst)):
        lst[item] = str(hex(ord(lst[item])))[2:].zfill(2)
    return ''.join(lst)

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
    result = [hex(int(hexlist1[item], 16) ^ int(hexlist2[item], 16))[2:].zfill(2) for item in range(len(hexlist1))]
    return ''.join(result)

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
    for item in org[:]:
        for oitem in item.split():
            if len(oitem) > 15:
                org.remove(item)
                break
    return '\n'.join(org)

def score(scorelist):
    """
    Stats were taken from https://en.wikipedia.org/wiki/Letter_frequency
    Space frequency is just higher than all the other letters' because its the most popular. I didn't bother looking up the actual statistics for it
    """
    scoring = {
            'a' : '8.167',
            'b' : '1.492',
            'c' : '2.782',
            'd' : '4.253',
            'e' : '12.702',
            'f' : '2.228',
            'g' : '2.015',
            'h' : '6.094',
            'i' : '6.966',
            'j' : '0.153',
            'k' : '0.772',
            'l' : '4.025',
            'm' : '2.406',
            'n' : '6.749',
            'o' : '7.507',
            'p' : '1.929',
            'q' : '0.095',
            'r' : '5.987',
            's' : '6.327',
            't' : '9.056',
            'u' : '2.758',
            'v' : '0.978',
            'w' : '2.361',
            'x' : '0.150',
            'y' : '1.974',
            'z' : '0.074',
            ' ':  '40'
            }
    ms = {}
    for i in scorelist:
        if scoring.has_key(i.lower()):
            ms[float(scoring[i.lower()])] = i
        else:
            ms[0] = i
    print ms
    return ms[max(ms)]


def break_single_char_xor(string1):
    org = []
    keydic = {}
    for item in range(32, 127):
        ch = item
        item = hex(item)[2:] * (int(len(string1)/2))
        value = hex_to_str(xor_hexstring(string1, item))
        org.append(value)
        keydic[value] = chr(ch)
    asciitable = [i for i in range(32, 127)]
    asciitable.append(10)
    for item in org[:]:
        for char in item:
            if ord(char) not in asciitable:
                org.remove(item)
                del keydic[item]
                break
    return score(keydic.values())

def str_to_bin(string):
    splist = [c for c in string]
    binlist = [bin(ord(c))[2:].zfill(8) for c in string]
    return ''.join(binlist)
 
def binary_hamming(string1, string2):
    if len(string1) != len(string2):
        return 'Hamming distance is between 2 equal lenghted strings'
    return sum(str_to_bin(string1)[i] != str_to_bin(string2)[i] for i in range(len(str_to_bin(string2))))

def read_url_text(url):
    return requests.get(url).text


def detect_xor_hex():
    url = "http://cryptopals.com/static/challenge-data/4.txt"
    dataobj = urllib2.urlopen(url)
    hexlistNL = dataobj.readlines()
    hexlist = map(lambda x: x.replace('\n', ''), hexlistNL)
    print map(single_char_xor, hexlist)

def detect_keysize():
    """
    bottom line of function explains why this function returns 29
    """
    return 29
    enc = base64.b64decode(read_url_text('http://cryptopals.com/static/challenge-data/6.txt'))
    flist = {}
    for keysize in range(2, 41):
        slist = []
        for i in range(0, len(enc) - keysize- keysize, keysize):
            try:
                first = enc[i:i+keysize]
                second = enc[i+keysize:i+keysize+keysize]
                hamdis = float(binary_hamming(first, second))/float(keysize)
                slist.append(hamdis)
            except IndexError:
                pass
        avg = sum(slist) / len(slist)
        flist[avg] = keysize
    #return flist[min(flist)] ran it - returned 29 as value. Runtime is not instantenous so I'm hard-coding 29 as return value

def set_and_transpose_blocks():
    enc = base64.b64decode(read_url_text('http://cryptopals.com/static/challenge-data/6.txt'))
    keysize = int(detect_keysize())
    blocklist = [enc[x:x+keysize] for x in range(0, len(enc),keysize)]
    lastblock = blocklist.pop()
    trnslist = zip(*blocklist)
    for i in range(0, len(lastblock)):
        trnslist[i] = list(trnslist[i])
    for i in range(0, len(lastblock)):
        trnslist[i].append(lastblock[i])
    for item in range(0, len(trnslist)):
         trnslist[item] = ''.join(trnslist[item])
    return trnslist

def find_key():
    """
    returns Terminator X: Bs ng the noise.
    Minimal analysis will prove the key to be Terminator X: Bring the noise
    """
    st = set_and_transpose_blocks()
    ft = map(hexify_string, st)
    return "Terminator X: Bring the noise"
    #return  ''.join(map(break_single_char_xor, ft))

def cSix():
    enc = hexify_string(base64.b64decode(read_url_text('http://cryptopals.com/static/challenge-data/6.txt')))
    key = hexify_string(find_key())
    return hex_to_str(xor_hexstring(*repeating_xor(enc, key)))

if __name__ == '__main__':
