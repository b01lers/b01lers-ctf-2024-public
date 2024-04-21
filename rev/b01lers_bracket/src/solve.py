from subprocess import Popen, PIPE
from pwn import *
import time

def conn():
    if args.LOCAL:
        r = process(["./b01lers_bracket"])
    else:
        # r = remote("localhost", 3082)
        r = remote("gold.b01le.rs", 4007)

    return r

def get_rng_bytes(data):
    lines = data.split('\n')

    team_bytes = {}

    def set_team_byte(team_name, wins, ppg):
        # print(team_name)
        # print(wins)
        # print(ppg)

        if team_name == 'Purdue':
            return

        base_ppg = 42 + (3 * wins) // 2
        ppg_diff = ppg - base_ppg
        ppg_offset = ppg_diff + 3

        random_byte = wins | (ppg_offset << 5)
        # print(random_byte)
        team_bytes[team_name] = random_byte

    for i in range(80):
        line = lines[i + 1]
        pieces = line.split('(')
        # print(line)
        # print(pieces)

        team_name = pieces[0].strip()
        wins = int(pieces[1].split('-')[0])
        ppg = int(pieces[2].split(' ')[0])

        set_team_byte(team_name, wins, ppg)

    def parse_region(lines):
        for i in range(16):
            p1 = lines[2 * i]
            p2 = lines[2 * i + 1]

            team_part = p1.split(':')[1]
            pieces = team_part.split('(')

            team_name = pieces[0].strip()
            wins = int(pieces[1].split('-')[0])
            ppg = int(p2.split('(')[1].split(' ')[0])

            set_team_byte(team_name, wins, ppg)

    def parse_region_name(name):
        region_part = data.split(name + '\n')[1]
        lines = region_part.split('\n')[:32]

        parse_region(lines)

    parse_region_name('East')
    parse_region_name('West')
    parse_region_name('South')
    parse_region_name('Midwest')

    team_names = ["VCU", "UC Santa Barbara", "Seton Hall", "Longwood", "Hartford", "Kentucky", "Charleston", "Montana State", "Miami", "Colgate", "Duquesne", "Texas A&M", "TCU", "Vermont", "Oklahoma State", "Wyoming", "Kennesaw State", "Marquette", "Creighton", "North Carolina", "Winthrop", "Memphis", "Wisconsin", "UAB", "Texas Tech", "Pittsburgh", "Illinois", "Oregon", "Rutgers", "Oregon State", "Eastern Washington", "Abilene Christian", "Liberty", "James Madison", "Southeast Missouri State", "Mount St. Mary's", "UConn", "St. Bonaventure", "Cal State Fullerton", "Princeton", "UNC Asheville", "Arkansas", "Mississippi State", "Grand Canyon", "Auburn", "LSU", "Gonzaga", "McNeese", "North Texas", "Georgia State", "NC State", "Washington State", "Boise State", "Notre Dame", "Missouri", "Chattanooga", "Penn State", "Maryland", "Saint Mary's", "West Virginia", "Ohio State", "Xavier", "Nebraska", "Alabama", "South Dakota State", "Syracuse", "Davidson", "Dayton", "Houston", "Michigan State", "Florida", "Stetson", "Saint Peter's", "Providence", "Louisiana", "New Mexico State", "Norfolk State", "North Carolina State", "South Carolina", "Ohio", "Wichita State", "Northwestern", "San Francisco", "Georgetown", "Morehead State", "Samford", "Akron", "Kansas State", "Iowa State", "Delaware", "Bryant", "Drake", "Duke", "Wright State", "Drexel", "Iowa", "Oklahoma", "Kent State", "Grambling State", "Murray State", "Arizona State", "Kansas", "Northern Kentucky", "UNC Greensboro", "BYU", "Nevada", "Colorado", "Texas", "UCLA", "Appalachian State", "Clemson", "Western Kentucky", "Purdue", "Wagner", "Loyola Chicago", "Fairleigh Dickinson", "Florida Atlantic", "Yale", "Texas A&M-Corpus Christi", "Oakland", "Utah State", "Tennessee", "Villanova", "Oral Roberts", "USC", "San Diego State", "Jacksonville State", "Colorado State", "Michigan", "Arizona", "Long Beach State", "Indiana", "Georgia Tech", "Richmond", "Virginia", "Texas Southern", "Cleveland State", "Iona", "Florida State", "Virginia Tech", "Baylor", "New Mexico", "Howard", "Furman"]
    raw_bytes = []

    for team_name in team_names:
        if team_name == 'Purdue':
            continue
        raw_bytes.append(team_bytes[team_name])

    return raw_bytes

def main():
    r = conn()
    team_data = r.recvuntil(b'====').decode('ascii')
    rng_bytes = get_rng_bytes(team_data)

    p = Popen("./solver", stdin=PIPE, stdout=PIPE, text=True)
    i = 0
    for n in rng_bytes[:128]:
        p.stdin.write(str(n) + '\n')
        p.stdin.flush()

    print('=================')

    for i in range(63):
        banner = r.recvline()
        prompt = r.recvline()
        c1 = r.recvline()
        team1 = r.recvline().decode('ascii')
        c2 = r.recvline()
        team2 = r.recvline().decode('ascii')

        seed1 = int(team1.split(':')[0])
        seed2 = int(team2.split(':')[0])

        print(f'seed1: {seed1}')
        print(f'seed2: {seed2}')

        p.stdin.write(str(seed1) + '\n')
        p.stdin.flush()
        p.stdin.write(str(seed2) + '\n')
        p.stdin.flush()

        line = p.stdout.readline().strip()
        print(line)

        if line == '1':
            r.sendline(b'1')
        else:
            r.sendline(b'2')

        print('done')

        r.recvline()
        r.recvline()
        r.recvline()

    r.interactive()

if __name__ == '__main__':
    main()
