from math import floor
from time import sleep
def minpal(string):
    str2 = [c for c in string]
    str1 = str2[:]
    if str1 == str1[-1::-1]:
        return 0
    #pivot = float(len(string))/2 - 1.5
    pivot = 0
    print pivot
    afp = 1
    ins = 0
    while str1 != str1[-1::-1]:
        sleep(0.5)
        print ''.join(str1)
        print afp
        av = float(len(str1))/2
        if av > pivot:
            side = 'r'
        else:
            side = 'l'
        if (floor(pivot) == pivot):
            print len(str1)
            if str1[int(floor(pivot)-afp)] != str1[int(floor(pivot) + afp)]:
                if side == 'r':
                    str1.insert(int(floor(pivot)-afp+1), str1[int(floor(pivot) + afp)])
                    ins+=1
                    pivot += 1
                else:
                    str1.insert(int(floor(pivot) + afp), str1[int(floor(pivot)-afp)])
                    ins+=1
            else:
                afp += 1
    return ''.join(str1)

if __name__ == '__main__':
    print minpal('slfmrhtjs')



    
