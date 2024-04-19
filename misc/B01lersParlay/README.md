# Writeup for B01lersParlay by vinhchilling
Difficulty: Easy. 45 solves / 434 points

## EDIT: after seeing people solve
The intended solve was way to complicated, neglecting simple API calls. My motivation is to create a CI/CD challenge in which players cannot see others' solves (you can see stuff other people do for a GitHub Action challenge). In the end, there is a simple solve that doesn't rely on CI at all. Credit CPCSEC for coming up with a simple solution:
``` curl --header "PRIVATE-TOKEN: [token-here]" https://gitlab.com/api/v4/projects/[project-id]/secure_files \
curl --header "PRIVATE-TOKEN: [token-here]" https://gitlab.com/api/v4/projects/[project-id]/secure_files/[id]/download
```
Moreover, people have permission to create new branch, make commits and do all sort of shenanegans. Only the main branch is protected. The permission for a token is not too granular, so for my intended solve to work I had to give it lots of privileges, which backfires sadly. At the end, I learned a lot from solves during the competition.

## Cloning the project
With the token and the URL, we can clone the project using 
```
git clone https://shazly:glpat-R-Td9nSxVAHW-72qxt5M@gitlab.com/b01lersparlay/GenerationalWealth.git
```

## Investigating
A little investigation will tell us that main branch has nothing, but origin/dev does. The **lint.rb** and **.gitlab-ci.yml** are very interesting:
```
def sacred_linter(input)
    if input =~ /^[0-9a-z=]+$/
      puts "safe"
    else
      puts "pwny?"
    end
  end

input = ENV['DECISION']

sacred_linter(input)
```
```
variables:
    DECISION: 'moneyin=123'
    SECURE_FILES_DOWNLOAD_PATH: $vault

cook_parlay:
  script:
    - lint_output=$(ruby ./lint.rb)
    - echo "$lint_output"
    - if [ "$lint_output" = "safe" ]; then eval "echo $DECISION"; else exit 1; fi
  artifacts:
    expire_in: 1s

  timeout: 1m
```

So ruby regex and eval huh :) If you haven't figured it out yet, try researching "dangerous ruby regex" and "Command Injection Eval".

## Exploit
So we need to modify the DECISION variable to get RCE, hopefully the shell on the GitLab runner. Alright, we have 1 minute before timeout and wait, where's the flag?

The memo talks about using secure files. That a legit feature of GitLab, you can read about them in the [official documentation](https://docs.gitlab.com/ee/ci/secure_files/). If we get shell on the runner, we can download the secure files using [this](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/download-secure-files). I put the SECURE_FILES_DOWNLOAD_PATH variable in just to guide everybody on the right direction. Not so secure huh?

Exploit chain is: Using "endline" or similar characters to bypass the regex matching, grab a shell on the runner, use the tool to download the secure file, and get the flag. You can also do everything with $DECISION and exfiltrate through a webhook, but I found that to be more cumbersome. 1 minute is so enough for the first option

Oh wait, I haven't mentioned how can you interact with the API and change the variable? The answer is: [invoke the pipeline using the api](https://docs.gitlab.com/ee/api/pipelines.html#create-a-new-pipeline). Make sure to include the token in the header, have the JSON in the correct format, and you should be good.

## Door for unintended solutions
The token has **api**, **readapi** and **read_repo** permission. I'm eager to see a better solution, proving your research skills on GitLab

## How is it possible:
The request to GitLab API can change the variable because *restrict_user_defined_variables=false* by [default](https://docs.gitlab.com/ee/ci/variables/index.html#restrict-who-can-override-variables). As mentioned in the above section, the token's permission allow us to first clone the repo, and use the API for exploit purposes. Also we have to give a big shoutout to **ruby regex** and **eval**.

## Bottom line
Hope yall have fun learning something about GitLab



