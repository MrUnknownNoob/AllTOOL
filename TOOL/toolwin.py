import base64
import hashlib
import random

print('''
 _____   ___    ___   _     
|_   _| / _ \  / _ \ | |    
  | |  | | | || | | || |    
  | |  | | | || | | || |    
  | |  | | | || | | || |    
  | |  | |_| || |_| || |___ 
  |_|   \___/  \___/ |_____|

            [+]    Developed By NOOB CODER    [+]  


01. Base 64
02. Base 16
03. Conversation
04. Case Convertor
05. Caracter Counter
06. Find And Replace
07. Line word Counter
08. Play with Hash
09. Hash Decryptor
10. Morse Code
11. Random Password Genarator
''')


select = int(input("Choose a Option::"))

if(select == 1):
    print('''
     ____   _____   ____  _____     ____  _   _ 
    |  _ \ |  _  | / ___||  ___|   / ___|| | | |
    | |_| || | | || |__  | |___   | |__  | |_| |
    |    / | |_| | \__ \ |  ___|  |  _ \ |___  |
    |  _ \ |  _  |    | || |      | | | |    | |
    | |_| || | | | ___| || |___   | |_| |    | |
    |____/ |_| |_||____/ |_____|   \___/     |_|
                          encrypted your Message

    01. Encode b64
    02. Decode b64
    ''')

    select = int(input("Select A Number::"))
    if(select == 1):
        strng1 = str(input("Enter your Anything::"))
        base64string1 = base64.b64encode(strng1.encode('ascii'))
        print('Encode in base 64:',base64string1)

    elif(select == 2):
        strng2 = str(input("Enter your Anything::"))
        base64string2 = base64.b64decode(strng2)
        print('decode in base 64:',base64string2)

    else:
        print("invalid Error")


elif(select == 2):
    print('''
     ____   _____   ____  _____    ___     ____ 
    |  _ \ |  _  | / ___||  ___|  |_  |   / ___|
    | |_| || | | || |__  | |___     | |  | |__  
    |    / | |_| | \__ \ |  ___|    | |  |  _ \ 
    |  _ \ |  _  |    | || |        | |  | | | |
    | |_| || | | | ___| || |___    _| |_ | |_| |
    |____/ |_| |_||____/ |_____|  |_____| \___/
                                  play with b16

    01. Encode With b16
    02. Decode With b16
    ''')

    select = int(input("Choose a Option::"))
    if(select == 1):
        data = input("Enter your Plain Text:")
        encoded = data.encode('utf-8')
        b16encoded = base64.b16encode(encoded)
        print("Your Encoded message is :",b16encoded)
    
    elif(select == 2):
        data = input("Enter your Coded Text:")
        print("Your Decoded message is :",base64.b16decode(data).decode('utf-8'))

    else:
        print("Invalid Error")


elif(select == 3):
    print('''
      ____   ___   _   _  _   _  _____  ____   _____  _____   ___   _   _ 
     /  __| / _ \ | \ | || | | ||  ___||  _ \ |_   _||_   _| / _ \ | \ | |
    |  /   | | | ||  \| || | | || |___ | |_| |  | |    | |  | | | ||  \| |
    | |    | | | || |\  || | | ||  ___||    /   | |    | |  | | | || |\  |
    | |    | | | || | | || |_| || |    | |\ \   | |    | |  | | | || | | |
    |  \__ | |_| || | | | \   / | |___ | | | |  | |   _| |_ | |_| || | | |
     \____| \___/ |_| |_|  \_/  |_____||_| |_|  |_|  |_____| \___/ |_| |_|
                                      Convert with binary,hexa,oct,decimal
                                  
    01. Decimal to Others
    02. Octal to Others
    03. Binary to Others
    ''')
    select = int(input("Select Your Option :"))

    if(select == 1):
        dec = int(input("Enter Decimal Number ::  "))
        print("Converted to Binary:",bin(dec))
        print("Converted to Hexa  :",hex(dec))
        print("Converted to Octal :",oct(dec))

    elif(select == 2):
        oct = int(input("Enter Octal Number ::  "))
        print("Converted to Binary:",bin(oct))
        print("Converted to Hexa:",hex(oct))

    elif(select == 3):
        bin = int(input("Enter Binary Number ::  "))
        print("Converted to Hexa:",hex(bin))
        print("Converted to Oct:",oct(bin))

    else:
        print("Invalid Error")  


elif(select == 4):
    print('''

      ____  _____   ____  _____     ____   ___   _   _  _   _  _____  ____   _____  _____  ____  
     /  __||  _  | / ___||  ___|   /  __| / _ \ | \ | || | | ||  ___||  _ \ |_   _||  ___||  _ \ 
    |  /   | | | || |__  | |___   |  /   | | | ||  \| || | | || |___ | |_| |  | |  | |___ | |_| |
    | |    | |_| | \__ \ |  ___|  | |    | | | || |\  || | | ||  ___||    /   | |  |  ___||    / 
    | |    |  _  |    | || |      | |    | | | || | | || |_| || |    | |\ \   | |  | |    | |\ \ 
    |  \__ | | | | ___| || |___   |  \__ | |_| || | | | \   / | |___ | | | |  | |  | |___ | | | |
     \____||_| |_||____/ |_____|   \____| \___/ |_| |_|  \_/  |_____||_| |_|  |_|  |_____||_| |_|
                                                                       change your case very fast

    01. lower case to Upper Case
    02. Upper Case to Lower Case
    03. Constant Case                                                                   
    ''')

    select = int(input("Select a Number :"))

    if(select == 1):
        a = str(input("Enter you Sentence: "))
        print("Your Upper Case is:",a.upper())

    elif(select == 2):
        a = str(input("Enter you Sentence: "))
        print("Your Lower Case is:",a.lower())

    elif(select == 3):
        a = str(input("Enter you Sentence: "))
        print("Your Lower Case is:",a.capitalize())

    else:
        print("InValid Error")  

elif(select == 5):
    print('''
      ____  _   _  _____  ____   _____   ____  _____  _____  ____      ____   ___   _   _  _   _  _____  _____  ____  
     /  __|| | | ||  _  ||  _ \ |  _  | /  __||_   _||  ___||  _ \    /  __| / _ \ | | | || \ | ||_   _||  ___||  _ \ 
    |  /   | | | || | | || |_| || | | ||  /     | |  | |___ | |_| |  |  /   | | | || | | ||  \| |  | |  | |___ | |_| |
    | |    | |_| || |_| ||    / | |_| || |      | |  |  ___||    /   | |    | | | || | | || |\  |  | |  |  ___||    / 
    | |    |  _  ||  _  || |\ \ |  _  || |      | |  | |    | |\ \   | |    | | | || | | || | | |  | |  | |    | |\ \ 
    |  \__ | | | || | | || | | || | | ||  \__   | |  | |___ | | | |  |  \__ | |_| || |_| || | | |  | |  | |___ | | | |
     \____||_| |_||_| |_||_| |_||_| |_| \____|  |_|  |_____||_| |_|   \____| \___/  \___/ |_| |_|  |_|  |_____||_| |_|
                                                                                            Text and character Counter

    01. Character Counter
    02. Word Counter By File
     ''')

    select = int(input("Select Any Thing:"))
    if(select == 1):
        a = str(input("Enter your Anything::"))
        print("Your Character is:", len(a))

    elif(select == 2):
        a = str(input("Select Your File Path::"))
        b = open(a, 'r')
        count = 0
        for line in b:
            words = line.split(" ")
            c = len(words)
            count = count + c
        b.close()    
        print("Number of Words is :",count)

    else:
        print("Invalid")

        
elif(select == 6):
    print('''
     _____  _____  _   _  ____     _____  _   _  ____     ____   _____  ____   _      _____   ____  _____ 
    |  ___||_   _|| \ | ||  _ \   |  _  || \ | ||  _ \   |  _ \ |  ___||  _ \ | |    |  _  | /  __||  ___|
    | |___   | |  |  \| || | | |  | | | ||  \| || | | |  | |_| || |___ | |_| || |    | | | ||  /   | |___ 
    |  ___|  | |  | |\  || | | |  | |_| || |\  || | | |  |    / |  ___||  __/ | |    | |_| || |    |  ___|
    | |      | |  | | | || | | |  |  _  || | | || | | |  | |\ \ | |    | |    | |    |  _  || |    | |    
    | |     _| |_ | | | || |_| |  | | | || | | || |_| |  | | | || |___ | |    | |___ | | | ||  \__ | |___ 
    |_|    |_____||_| |_||____/   |_| |_||_| |_||____/   |_| |_||_____||_|    |_____||_| |_| \____||_____|
                                                                                            Find & Replace

    ''')


    a = str(input("Enter ANy Thing:"))
    b = str(input("What is your Target word:"))
    c = str(input("What Word to you replace:"))
    print(a.replace(str(b),str(c)))  


elif(select == 7):
    print('''
     _      _____  _   _  _____    _   _   ___   ____   ____      ____   ___   _   _  _   _  _____  _____  ____  
    | |    |_   _|| \ | ||  ___|  | | | | / _ \ |  _ \ |  _ \    /  __| / _ \ | | | || \ | ||_   _||  ___||  _ \ 
    | |      | |  |  \| || |___   | |_| || | | || |_| || | | |  |  /   | | | || | | ||  \| |  | |  | |___ | |_| |
    | |      | |  | |\  ||  ___|  | / \ || | | ||    / | | | |  | |    | | | || | | || |\  |  | |  |  ___||    / 
    | |      | |  | | | || |      |  _  || | | || |\ \ | | | |  | |    | | | || | | || | | |  | |  | |    | |\ \ 
    | |___  _| |_ | | | || |___   | / \ || |_| || | | || |_| |  |  \__ | |_| || |_| || | | |  | |  | |___ | | | |
    |_____||_____||_| |_||_____|  |/   \| \___/ |_| |_||____/    \____| \___/  \___/ |_| |_|  |_|  |_____||_| |_|
                                                                                      line word character counter
                                                                                ''')

    filepath = input("Enter the File path:")
    numlines = 0
    numwords = 0
    numchar = 0

    handle = open(filepath, 'r')
    for line in handle:
            wordlist = line.split()
            numlines = numlines + 1
            numwords += len(wordlist)
            numchar += len(line)
    print(f"[+]There Are:::\n[+]Lines are :{numlines}\n[+]words are::: {numwords}\n[+]characters are ::{numchar}") 


elif(select == 8):
    print('''
     ____   _      _____  _     _    _   _  _____  _____  _   _    _   _  _____   ____  _   _ 
    |  _ \ | |    |  _  |\ \   / /  | | | ||_   _||_   _|| | | |  | | | ||  _  | / ___|| | | |
    | |_| || |    | | | | \ \_/ /   | |_| |  | |    | |  | | | |  | | | || | | || |__  | | | |
    |  __/ | |    | |_| |  \   /    | / \ |  | |    | |  | |_| |  | |_| || |_| | \__ \ | |_| |
    | |    | |    |  _  |   | |     |  _  |  | |    | |  |  _  |  |  _  ||  _  |    | ||  _  |
    | |    | |___ | | | |   | |     | / \ | _| |_   | |  | | | |  | | | || | | | ___| || | | |
    |_|    |_____||_| |_|   |_|     |/   \||_____|  |_|  |_| |_|  |_| |_||_| |_||____/ |_| |_|
                                                                           just play with Hash

    01. Encrypted with md5
    02. Encrypted with sha1
    03. Encrypted with sha224
    04. Encrypted with sha256
    05. Encrypted with sha384
    06. Encrypted with sha512
    ''')

    select = int(input("Choose A Type::"))

    if(select == 1):
        text = str(input("Enter your Message::")) 
        hashobj = hashlib.md5(text.encode())
        md5hash = hashobj.hexdigest()
        print("Your MD5 Hash is :",md5hash)

    elif(select == 2):
        text = str(input("Enter your Message::")) 
        hashobj = hashlib.sha1(text.encode())
        sha1hash = hashobj.hexdigest()
        print("Your Sha1 Hash is :",sha1hash)

    elif(select == 3):
        text = str(input("Enter your Message::")) 
        hashobj = hashlib.sha224(text.encode())
        sha224hash = hashobj.hexdigest()
        print("Your Sha224 Hash is :",sha224hash)

    elif(select == 4):
        text = str(input("Enter your Message::")) 
        hashobj = hashlib.sha256(text.encode())
        sha256hash = hashobj.hexdigest()
        print("Your Sha256 Hash is :",sha256hash)

    elif(select == 5):
        text = str(input("Enter your Message::")) 
        hashobj = hashlib.sha384(text.encode())
        sha384hash = hashobj.hexdigest()
        print("Your Sha384 Hash is :",sha384hash)

    elif(select == 6):
        text = str(input("Enter your Message::")) 
        hashobj = hashlib.sha512(text.encode())
        sha512hash = hashobj.hexdigest()
        print("Your Sha512 Hash is :",sha512hash)

    else:
        print("Invalid Error")

elif(select == 9):
    print('''
    
     _   _  _____   ____  _   _    ____   _____   ____  ____   _     _  ____   _____   ___   ____  
    | | | ||  _  | / ___|| | | |  |  _ \ |  ___| /  __||  _ \ \ \   / /|  _ \ |_   _| / _ \ |  _ \ 
    | | | || | | || |__  | | | |  | | | || |___ |  /   | |_| | \ \_/ / | |_| |  | |  | | | || |_| |
    | |_| || |_| | \__ \ | |_| |  | | | ||  ___|| |    |    /   \   /  |  __/   | |  | | | ||    / 
    |  _  ||  _  |    | ||  _  |  | | | || |    | |    | |\ \    | |   | |      | |  | | | || |\ \ 
    | | | || | | | ___| || | | |  | |_| || |___ |  \__ | | | |   | |   | |      | |  | |_| || | | |
    |_| |_||_| |_||____/ |_| |_|  |____/ |_____| \____||_| |_|   |_|   |_|      |_|   \___/ |_| |_|
                                                                              Decrypted Hash Format
    01. Decode With MD5
    02. Decode With SHA 1
    03. Decode With SHA 224 
    04. Decode With SHA 256 
    05. Decode With SHA 384 
    06. Decode With SHA 512
    
    ''')


    select = int(input("Choose A Option :"))

    if(select==1): 
        hashcode = str(input("Enter your hash::"))
        filepath = str(input("Enter the File Path :"))

        def hash(inputhash):

            try:
                passfile = open(filepath, "r")  
            except:
                print("Could not Find File.")


            for password in passfile:
                encPass = password.encode("utf-8")
                digest = hashlib.md5(encPass.strip()).hexdigest()
                if digest == inputhash:
                    print("Password Found :",password)
           
        if __name__ == "__main__":
            hash(hashcode)

    elif(select==2): 
        hashcode = str(input("Enter your hash::"))
        filepath = str(input("Enter the File Path :"))

        def hash(inputhash):

            try:
                passfile = open(filepath, "r")  
            except:
                print("Could not Find File.")


            for password1 in passfile:
                encPass = password1.encode("utf-8")
                digest = hashlib.sha1(encPass.strip()).hexdigest()
                if digest == inputhash:
                    print("Password Found :",password1)
           
        if __name__ == "__main__":
            hash(hashcode)

    elif(select==3): 
        hashcode = str(input("Enter your hash::"))
        filepath = str(input("Enter the File Path :"))

        def hash(inputhash):

            try:
                passfile = open(filepath, "r")  
            except:
                print("Could not Find File.")


            for password in passfile:
                encPass = password.encode("utf-8")
                digest = hashlib.sha224(encPass.strip()).hexdigest()
                if digest == inputhash:
                    print("Password Found :",password)
           
        if __name__ == "__main__":
            hash(hashcode)
    
    elif(select==4): 
        hashcode = str(input("Enter your hash::"))
        filepath = str(input("Enter the File Path :"))

        def hash(inputhash):

            try:
                passfile = open(filepath, "r")  
            except:
                print("Could not Find File.")


            for password in passfile:
                encPass = password.encode("utf-8")
                digest = hashlib.sha256(encPass.strip()).hexdigest()
                if digest == inputhash:
                    print("Password Found :",password)
           
        if __name__ == "__main__":
            hash(hashcode)
    
    elif(select==5): 
        hashcode = str(input("Enter your hash::"))
        filepath = str(input("Enter the File Path :"))

        def hash(inputhash):

            try:
                passfile = open(filepath, "r")  
            except:
                print("Could not Find File.")


            for password in passfile:
                encPass = password.encode("utf-8")
                digest = hashlib.sha384(encPass.strip()).hexdigest()
                if digest == inputhash:
                    print("Password Found :",password)
           
        if __name__ == "__main__":
            hash(hashcode)
    
    elif(select==6): 
        hashcode = str(input("Enter your hash::"))
        filepath = str(input("Enter the File Path :"))

        def hash(inputhash):

            try:
                passfile = open(filepath, "r")  
            except:
                print("Could not Find File.")


            for password in passfile:
                encPass = password.encode("utf-8")
                digest = hashlib.sha512(encPass.strip()).hexdigest()
                if digest == inputhash:
                    print("Password Found :",password)
           
        if __name__ == "__main__":
            hash(hashcode)
    else:
        print("Invalid Error")



elif(select == 10):
    print('''

     _    _   ___   ____    ____  _____     ____   ___   ____   _____ 
    | \  / | / _ \ |  _ \  / ___||  ___|   /  __| / _ \ |  _ \ |  ___|
    |  \/  || | | || |_| || |__  | |___   |  /   | | | || | | || |___ 
    |      || | | ||    /  \__ \ |  ___|  | |    | | | || | | ||  ___|
    | |\/| || | | || |\ \     | || |      | |    | | | || | | || |    
    | |  | || |_| || | | | ___| || |___   |  \__ | |_| || |_| || |___ 
    |_|  |_| \___/ |_| |_||____/ |_____|   \____| \___/ |____/ |_____|
                                                 play with morse Code
                        ''')



    morsecode = {
    'A' : '.-',
    'B' : '-...',
    'C' : '-.-.',
    'D' : '-..',
    'E' : '.',
    'F' : '..-.',
    'G' : '--.',
    'H' : '....',
    'I' : '..',
    'J' : '.---',
    'K' : '-.-',
    'L' : '.-..',
    'M' : '--',
    'N' : '-.',
    'O' : '---',
    'P' : '.--.',
    'Q' : '--.-',
    'R' : '.-.',
    'S' : '...',
    'T' : '-',
    'U' : '..-',
    'V' : '...-',
    'W' : '.--',
    'X' : '-..-',
    'Y' : '-.--',
    'Z' : '--..',
    '0' : '-----',
    '1' : '.----',
    '2' : '.----',
    '3' : '...--',
    '4' : '....-',
    '5' : '.....',
    '6' : '-....',
    '7' : '--...',
    '8' : '---..',
    '9' : '----.'
        }


    def encryptor(text):
        encryptedtext = ""
        for letters in text:
            if letters != " ":
                encryptedtext = encryptedtext + morsecode.get(letters) + " "
            else:
                encryptedtext = encryptedtext + " "


        print(encryptedtext)    

    def decryptor(text):
        text = text + " "

        key = list(morsecode.keys())
        val = list(morsecode.values())
        morse = ""
        normal = ""

        for letters in text:
            if letters != " ":
                morse = morse + letters
                spacefound = 0

            else:
                spacefound = spacefound + 1
                if spacefound == 2:
                    normal = normal + ""
                else:
                    normal = normal + key[val.index(morse)]
                    morse = ""
        print(normal)




    print("\n\n\n\t\tMorse Code Genarator")
    ch = input("Press 'E' to Encrypted Or 'D' to Decypted :")
    if ch == 'E' or ch == 'e':
        texttoencrypted = input("Enter Some Text to Encrypt :").upper()
        encryptor(texttoencrypted)
    else :
        texttodecrypted = input("Enter Morse code to Decrypt :")
        decryptor(texttodecrypted)    


elif(select == 11):

    print('''

    ____   _____  _   _  ____    ___   _    _    ____   _____   ____   ____    _____  _____  _   _ 
    |  _ \ |  _  || \ | ||  _ \  / _ \ | \  / |  |  _ \ |  _  | / ___| / ___|  | ____||  ___|| \ | |
    | |_| || | | ||  \| || | | || | | ||  \/  |  | |_| || | | || |__  | |__    ||  __ | |___ |  \| |
    |    / | |_| || |\  || | | || | | ||      |  |  __/ | |_| | \__ \  \__ \   || |_ ||  ___|| |\  |
    | |\ \ |  _  || | | || | | || | | || |\/| |  | |    |  _  |    | |    | |  ||   ||| |    | | | |
    | | | || | | || | | || |_| || |_| || |  | |  | |    | | | | ___| | ___| |  ||___||| |___ | | | |
    |_| |_||_| |_||_| |_||____/  \___/ |_|  |_|  |_|    |_| |_||____/ |____/   |_____||_____||_| |_|
                                                                       Random Password Genarator
    01. Random Password Genarator Type Only password Length
    02. Random Password Genarator Type Only some Character
    03. Random Password Genarator Type Only password Length
    ''')

    a = int(input("Choose Your Option :"))

    if (a == 1):
        lower  = "abcdefghijklmnopqrstuvwxyz"
        upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        number = "0123456789"
        symbol = "!@#$%^&*(),./;'\][<>?:|}{"

        string = lower + upper + number + symbol
        length = int(input("Password Length :"))

        password = "".join(random.sample(string,length))

        print("Your New Password is :", password)


    elif (a == 2):
        a = input("Enter your Some character :")
        b  = list(str(a))
        random.shuffle(b)
        print("Your New Password is :",''.join(b))

    elif(a == 3):
    
        password = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,./;'\][<>?:|{}!@#$%^&*()_+=-"
        passlen = int(input("Enter the Length of the password::"))
        a = "".join(random.sample(password,passlen))
        print("Your Password is:",a)


    else:
        print("Syntax Error")



else:
    print('Invalid Error')