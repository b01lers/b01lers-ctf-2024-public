# Writeup for 3-city-elves-writeups by VinhChilling 
Difficulty: Easy. 43 solves / 438 points

## Motivation
Sadly, you won't get it if you didn't compete in [ectf 2024](https://ectfmitre.gitlab.io/ectf-website/index.html), entered the Attack Phase, completed an attack and get to submit a writeup. There's a WAF checking the content of the writeup, so if you submit something suspicious like:
``` | grep ```
then your submission will not go through

## Solving the challenge
The challenge is a Command Injection one. In **waf.py**, I just had ChatGPT generated a crazy long list, but ineffective. I put some character blacklisting in as well to make it spicy, but for people with bash jail experience that's trivial. 

My intended solution is using *${HOME:0:1}* to get the backslash, then use wildcard (*) to bypass the *word filtering*. For reliability, I recommend getting reverse shell and then you have the freedom to exfiltrate the picture. It saves you from not knowing what went wrong with your payload.

Shoutout to short payloads:
![image](https://github.com/b01lers/b01lers-ctf-2024/assets/111932850/f51f1e45-65ee-4911-b3c0-ea235f634bbc)

## Bottom line
I recommend [HackTrick](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions) for neat bypasses, and as always the more you do it the better you become. Honestly, I had hoped that more people get the joke but hey I learned a lot from people solves. I saw some very creative attempt in tickets. 
