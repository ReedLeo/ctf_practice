graph = [
    [0, 1, 1, 1, 1, 1, 1, 1, 1, 1], 
    [0, 0, 0, 1, 1, 1, 0, 0, 0, 0], 
    [1, 1, 0, 0, 1, 1, 0, 1, 0, 1], 
    [1, 1, 1, 0, 1, 1, 0, 1, 0, 1], 
    [1, 0, 0, 0, 0, 0, 0, 1, 0, 1], 
    [1, 0, 0, 1, 1, 1, 1, 1, 0, 1], 
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 1], 
    [1, 0, 0, 0, 1, 1, 1, 1, 1, 1], 
    [1, 0, 1, 0, 0, 0, 1, 0, 0, 0], 
    [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
]

def bfs():
    que = [(0, 0, [(0, 0)])]
    vis = set()
    while que:
        x, y, path = que.pop(0)
        if (x, y) == (9, 9):
            return path
        if (x, y) in vis:
            continue
        vis.add((x, y))
        l, r, u, d = y - 1, y + 1, x - 1, x + 1
        if l >= 0 and graph[x][l] == 0:
            que.append((x, l, path+[(x, l)]))
        if r < len(graph[0]) and graph[x][r] == 0:
            que.append((x, r, path+[(x, r)]))
        if u >= 0 and graph[u][y] == 0:
            que.append((u, y, path+[(u, y)]))
        if d < len(graph) and graph[d][y] == 0:
            que.append((d, y, path+[(d, y)]))
    return []

path = bfs()
footprint = '3qzqns4hj6\neeaxc!4a-%\nd735_@4l6g\nf1gd1v7hdm\n1+$-953}81\na^21vbnm3!\n-#*f-e1d8_\n2ty9uipok-\n6r1802f7d1\n9wez1c-f{0'
xx0000 = []
footprintlist = footprint.split('\n')
for i in range(len(footprintlist)):
    xx0000.append(list(footprintlist[i]))

flag = ''.join(map(lambda pos: xx0000[pos[0]][pos[1]], path))
print('flag{%s}' % flag)
# flag{3eea35d-953744a-6d838d1e-f9802c-f7d10}