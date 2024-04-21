#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "rb_rng.h"

#define NUM_GAMES 32
#define NUM_TEAMS 144

// certain teams are treated specially
typedef enum {
  Purdue,
  Other,
} TeamId;

typedef struct {
  const char *name;
  u8 wins;
  u8 points_per_game;
  u8 seed;
  // Treats certain teams specially
  TeamId id;
} Team;

void team_print(Team *team) {
  printf("%u: %s (%d-%d)\n", team->seed, team->name, team->wins, NUM_GAMES - team->wins);
}

typedef struct {
  Team *team1;
  Team *team2;
  Team **winner;
} Match;

Team *match_get_winner(Match *match, RbRng *rng) {
  // high seed on team2 gives weight to team 1
  i8 seed_diff = (i8) match->team2->seed - (i8) match->team1->seed;
  // 16 * 6 == 96 / 128 weight that is afffected by seed
  i8 threshhold = 4 * seed_diff;
  i8 random = (i8) rb_rng_next_byte(rng);

  // if random above threshhold, team2 won
  return random > threshhold ? match->team2 : match->team1;
}

typedef struct {
  Team *rounds[128];
} Bracket;
size_t base_index[7] = {0, 64, 96, 112, 120, 124, 126};
size_t round_match_count[6] = {32, 16, 8, 4, 2, 1};

Team **bracket_get_team(Bracket *bracket, size_t round, size_t team_index) {
  return &bracket->rounds[base_index[round] + team_index];
}

Match bracket_get_match(Bracket *bracket, size_t round, size_t match) {
  Match out;

  size_t teams_in_round = 2 * round_match_count[round];
  size_t team1_index;
  size_t team2_index;
  if (teams_in_round > 4) {
    size_t matches_per_division = round_match_count[round] / 4;

    size_t match_num = match % matches_per_division;
    size_t offset = match / matches_per_division;

    team1_index = (2 * matches_per_division) * offset + match_num;
    team2_index = (2 * matches_per_division) * offset + (teams_in_round / 4) - match_num - 1;
  } else {
    team1_index = 2 * match;
    team2_index = 2 * match + 1;
  }

  out.team1 = *bracket_get_team(bracket, round, team1_index);
  out.team2 = *bracket_get_team(bracket, round, team2_index);
  out.winner = bracket_get_team(bracket, round + 1, match);
  return out;
}

size_t get_num() {
  char n[16];
  fgets(n, 8, stdin);
  char *end = NULL;
  for (;;) {
    size_t out = strtoul(n, &end, 0);
    if (end != NULL && (*end != '\n' || end == n)) {
      // check end is pointing at newline and it is past n
      puts("invalid number");
      fgets(n, 8, stdin);
    } else {
      return out;
    }
  }
}

// returns if match was predicted correctly
bool bracket_predict_match(Bracket *bracket, RbRng *rng, size_t round, size_t match) {
  Match m = bracket_get_match(bracket, round, match);

  printf("==== Round %lu Match %lu ====\n", round + 1, match + 1);
  puts("Select the team you think will win! (enter 1 or 2)");
  puts("    choice 1:");
  team_print(m.team1);
  puts("    choice 2:");
  team_print(m.team2);

  size_t n = 0;
  for (;;) {
    n = get_num();
    if (n != 1 && n != 2) {
      puts("invalid choice");
    } else {
      break;
    }
  }

  Team *predicted_winner = n == 1 ? m.team1 : m.team2;
  Team *actual_winner = match_get_winner(&m, rng);

  *m.winner = actual_winner;

  if (predicted_winner != actual_winner) {
    puts("Incorrect, the actual winner is:");
    team_print(actual_winner);
    puts("\n");

    return false;
  } else {
    puts("Correct!");
    puts("\n");

    return true;
  }
}

const char *region_to_str(size_t region) {
  switch (region) {
    case 0:
      return "East";
    case 1:
      return "West";
    case 2:
      return "South";
    case 3:
      return "Midwest";
    default:
      return "";
  }
}

const char *team_names[NUM_TEAMS] = {"VCU", "UC Santa Barbara", "Seton Hall", "Longwood", "Hartford", "Kentucky", "Charleston", "Montana State", "Miami", "Colgate", "Duquesne", "Texas A&M", "TCU", "Vermont", "Oklahoma State", "Wyoming", "Kennesaw State", "Marquette", "Creighton", "North Carolina", "Winthrop", "Memphis", "Wisconsin", "UAB", "Texas Tech", "Pittsburgh", "Illinois", "Oregon", "Rutgers", "Oregon State", "Eastern Washington", "Abilene Christian", "Liberty", "James Madison", "Southeast Missouri State", "Mount St. Mary's", "UConn", "St. Bonaventure", "Cal State Fullerton", "Princeton", "UNC Asheville", "Arkansas", "Mississippi State", "Grand Canyon", "Auburn", "LSU", "Gonzaga", "McNeese", "North Texas", "Georgia State", "NC State", "Washington State", "Boise State", "Notre Dame", "Missouri", "Chattanooga", "Penn State", "Maryland", "Saint Mary's", "West Virginia", "Ohio State", "Xavier", "Nebraska", "Alabama", "South Dakota State", "Syracuse", "Davidson", "Dayton", "Houston", "Michigan State", "Florida", "Stetson", "Saint Peter's", "Providence", "Louisiana", "New Mexico State", "Norfolk State", "North Carolina State", "South Carolina", "Ohio", "Wichita State", "Northwestern", "San Francisco", "Georgetown", "Morehead State", "Samford", "Akron", "Kansas State", "Iowa State", "Delaware", "Bryant", "Drake", "Duke", "Wright State", "Drexel", "Iowa", "Oklahoma", "Kent State", "Grambling State", "Murray State", "Arizona State", "Kansas", "Northern Kentucky", "UNC Greensboro", "BYU", "Nevada", "Colorado", "Texas", "UCLA", "Appalachian State", "Clemson", "Western Kentucky", "Purdue", "Wagner", "Loyola Chicago", "Fairleigh Dickinson", "Florida Atlantic", "Yale", "Texas A&M-Corpus Christi", "Oakland", "Utah State", "Tennessee", "Villanova", "Oral Roberts", "USC", "San Diego State", "Jacksonville State", "Colorado State", "Michigan", "Arizona", "Long Beach State", "Indiana", "Georgia Tech", "Richmond", "Virginia", "Texas Southern", "Cleveland State", "Iona", "Florida State", "Virginia Tech", "Baylor", "New Mexico", "Howard", "Furman"};
Team teams[NUM_TEAMS];

void bracket_print_seeds(Bracket *bracket) {
  puts("Teams that didn't make the bracket:");
  for (size_t i = 64; i < NUM_TEAMS; i++) {
    printf("%s (%d-%d) (%u points per game)\n", teams[i].name, teams[i].wins, NUM_GAMES - teams[i].wins, teams[i].points_per_game);
  }
  printf("\n");

  for (size_t region = 0; region < 4; region++) {
    puts(region_to_str(region));
    for (size_t seed = 0; seed < 16; seed++) {
      Team *team = *bracket_get_team(bracket, 0, 16 * region + seed);
      team_print(team);
      printf("    (%u points per game)\n", team->points_per_game);
    }
    printf("\n");
  }
}

void sort_teams() {
  size_t sorted_start = 1;

  for (size_t i = 1; i < NUM_TEAMS; i++) {
    for (size_t j = i; j > 0; j--) {
      if (teams[j - 1].wins < teams[j].wins) {
        Team temp = teams[j - 1];
        teams[j - 1] = teams[j];
        teams[j] = temp;
      }
    }
  }
}

void init_and_rank_teams(RbRng *rng) {
  for (size_t i = 0; i < NUM_TEAMS; i++) {
    teams[i].name = team_names[i];
    if (strcmp(teams[i].name, "Purdue") == 0) {
      teams[i].id = Purdue;
      teams[i].wins = 29;
      teams[i].points_per_game = 82;
    } else {
      teams[i].id = Other;
      u8 random = rb_rng_next_byte(rng);
      // first 5 bits are used for wins
      teams[i].wins = random & 0x1f;

      // 0 wins is 42 points per game, 32 wins is 90 points per game
      u32 base_points_per_game = 42 + (3 * ((u32) teams[i].wins)) / 2;
      // the last 3 bits are used as on additional addition to the points per game
      u8 other_bits = (random & 0xe0) >> 5;
      i8 offset = (i8) other_bits - 3;

      u8 points_per_game = (i8) base_points_per_game + offset;

      teams[i].points_per_game = (i8) base_points_per_game + offset;
    }
  }

  sort_teams();
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  RbRng rng = rb_rng_from_os_random();

  init_and_rank_teams(&rng);

  Bracket bracket;
  for (size_t i = 0; i < 128; i++) {
    bracket.rounds[i] = NULL;
  }

  for (size_t i = 0; i < 16; i++) {
    for (size_t region = 0; region < 4; region++) {
      size_t index = 4 * i + region;
      teams[index].seed = i + 1;
      bracket.rounds[16 * region + i] = &teams[index];
    }
  }

  bracket_print_seeds(&bracket);

  puts("Can you predict all the matches correctly?");

  for (size_t round = 0; round < 6; round++) {
    for (size_t match = 0; match < round_match_count[round]; match++) {
      if (!bracket_predict_match(&bracket, &rng, round, match)) {
        puts("You did not predict all the matches correctly :(");
        return 0;
      }
    }
  }

  puts("You predicted all the matches correctly! Here is your reward:");
  FILE *file = fopen("flag.txt", "r");
  if (file == NULL) {
    puts("Flag file not found");
  } else {
    char flag[128];
    fgets(flag, 128, file);
    puts(flag);
  }
}
