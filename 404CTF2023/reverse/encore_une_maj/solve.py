import re
import string

# Found cody value thanks to debug on source code
cody = 518

def parse():
    coef, result = [], []
    with open("./conditions.txt", "r") as f:
        content = f.read()
        for i in range(0,48,3):
            pattern = f".*\[{i}\].*\[{i+1}\].*\[{i+2}\].*"
            regex = re.compile(pattern)
            matched = regex.findall(content)
            
            loop_coef, loop_result = [], []
            for elt in matched:
                line_coef = []
                eq, res = elt.split(" == ")
                res = int(res)
                eq = eq.split(" + ")
                for term in eq:
                    if "cody" in term:
                        line_coef.append(cody)
                    else:
                        line_coef.append(1)
                loop_coef.append(line_coef)
                loop_result.append(res)
            coef.append(loop_coef), result.append(loop_result)
    return coef, result
                        
def solve(coef, res): 
    for u in string.printable:
        for v in string.printable:
            for w in string.printable:
                carmen = 0
                c = ord(u)
                c2 = ord(v)
                c3 = ord(w)
                for i in range(4):
                    if coef[i][0]*c + coef[i][1]*c2 + coef[i][2]*c3 == res[i]:
                        carmen += 1
                if carmen == 2:
                    return chr(c) + chr(c2) + chr(c3)
                
coef, res = parse() 

flag = ""    
for i in range(16):
    flag += solve(coef[i], res[i])
    
print(flag)
