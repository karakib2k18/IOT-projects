from attacker import Attacker

paths = [
    ["devA","gw","devB"],
    ["devA","devB"]
]

print("gateway p=1.0:", [Attacker("gateway",1.0,42).try_intercept(p) for p in paths])
print("global  p=0.5:", [Attacker("global",0.5,42).try_intercept(p) for p in paths])
print("link devA-gw :", [Attacker([("devA","gw")], {("devA","gw"):1.0},42).try_intercept(p) for p in paths])
