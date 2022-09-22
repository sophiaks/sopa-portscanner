import re

file = open('shadow', 'r')
lines =  file.readlines()
pattern = lines[0]

pass_encryption_dict = {
    '1': 'MD5',
    '2': 'Blowfish',
    '2a': 'eksblowfish',
    '5': 'SHA-256',
    '6': 'SHA-512'
}

_enc = re.search("\$(.*?)\$", pattern).group(0)
encryption_type = re.sub(r'[^\w]', '', _enc)

print(f"The type of encryption of this password is {pass_encryption_dict[encryption_type]}")
