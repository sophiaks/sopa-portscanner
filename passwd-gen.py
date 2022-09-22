import itertools

def pass_gen(min, max):
    char_list = 'calvo'
    passwds = list(map("".join, itertools.product(char_list, repeat=5)))
    print(passwds)

pass_gen(1, 2)