import angr

possibleJmps = [
    {
        "name": "jz",
        "must": [0x40],
        "not": [0x1, 0],
        "priority": 1
    },
    {
        "name": "jo",
        "must": [0x800],
        "not": [0],
        "priority": 1
    },
    {
        "name": "jno",
        "must": [0x40],
        "not": [0x800],
        "priority": 1
    },
    {
        "name": "jp",
        "must": [0x4],
        "not": [0],
        "priority": 1
    },
    {
        "name": "jnp",
        "must": [0],
        "not": [0x4],
        "priority": 1
    },
    {
        "name": "jb",
        "must": [0x1],
        "not": [0],
        "priority": 1
    },
    {
        "name": "jnb",
        "must": [0],
        "not": [0x1],
        "priority": 1
    },
    {
        "name": "ja",
        "must": [0],
        "not": [0x40, 0x1, 0x41],
        "priority": 2
    },
    {
        "name": "jl",
        "must": [0x800, 0x80],
        "not": [0x880, 0],
        "priority": 2
    },
    {
        "name": "jge",
        "must": [0x880, 0],
        "not": [0x800, 0x80],
        "priority": 2
    },
    {
        "name": "jg",
        "must": [0x880, 0],
        "not": [0x8C0, 0x800, 0x80],
        "priority": 3
    },
    {
        "name": "jnz",
        "must": [0x1, 0],
        "not": [0x40],
        "priority": 1
    },
    {
        "name": "jbe",
        "must": [0x41, 0x40, 0x1],
        "not": [0],
        "priority": 2
    },
    {
        "name": "jle",
        "must": [0x40, 0xC0, 0x840, 0x80, 0x800],
        "not": [0x880, 0],
        "priority": 3
    },
    {
        "name": "js",
        "must": [0x80],
        "not": [0],
        "priority": 1
    },
    {
        "name": "jns",
        "must": [0],
        "not": [0x80],
        "priority": 1
    },
]

controlFlowBits = 0x8C5


def getStatesMap(proj):
    statesMap = {}

    state = proj.factory.blank_state(addr=0x0)
    state.add_constraints(state.regs.edx >= 0)
    state.add_constraints(state.regs.edx <= 15)
    simgr = proj.factory.simulation_manager(state)
    r = simgr.explore(find=0xDA, avoid=0xDE, num_find=100)

    for state in r.found:
        val = state.solver.eval(state.regs.edx)
        val = val - 0xD
        val = val / 2

        if(not statesMap.has_key(val)):
            statesMap[val] = {"must": [], "not": []}

        statesMap[val]["must"].append(state)

    state = proj.factory.blank_state(addr=0x0)
    state.add_constraints(state.regs.edx >= 0)
    state.add_constraints(state.regs.edx <= 15)
    simgr = proj.factory.simulation_manager(state)
    r = simgr.explore(find=0xDE, avoid=0xDA, num_find=100)

    for state in r.found:
        val = state.solver.eval(state.regs.edx)
        val = val - 0xD
        val = val / 2

        statesMap[val]["not"].append(state)

    return statesMap

proj = angr.Project("jmpDecoder.bin", main_opts={'backend': 'blob', 'custom_arch': 'i386'}, auto_load_libs=False)

#result = simgr.step()
#resultState = result.active[0]
#resultState.solver.eval(resultState.regs.eip)



stateMap = getStatesMap(proj)
jumpMappings = {}
for key, val in stateMap.iteritems():

    for jmp in possibleJmps:
        satisfiedMustsRemaining = len(jmp["must"])
        satisfiedNotsRemaining = len(jmp["not"])

        for state in val["must"]:
            for con in jmp["must"]:
                if (state.solver.satisfiable(
                        extra_constraints=[state.regs.eax & controlFlowBits == con & controlFlowBits])):
                    satisfiedMustsRemaining -= 1;

        for state in val["not"]:
            for con in jmp["not"]:
                if (state.solver.satisfiable(
                        extra_constraints=[state.regs.eax & controlFlowBits == con & controlFlowBits])):
                    satisfiedNotsRemaining -= 1;

        if(satisfiedMustsRemaining <= 0 and satisfiedNotsRemaining <= 0):
            if(not jumpMappings.has_key(key)):
                jumpMappings[key] = []

            jumpMappings[key].append(jmp)
            print(str(key) + " to jump " + jmp["name"] + " Priority " + str(jmp["priority"]))

print("============")
for key, val in jumpMappings.iteritems():
    maxPriority = 0;
    jmpName = "NOE FOUND"
    for j in val:
        if(j["priority"] > maxPriority):
            maxPriority = j["priority"]
            jmpName = j["name"]

    print("Mapped " + str(key) + " to " + jmpName)

