# Writeup for b02lers by King Fish

### Solve

A first glance at the discord doesn't show the flag on the client. There isn't anything in the events tab, channels, members, emojis, etc. The message in #general is just bait. That means we'll have to go deeper. 

First we check for hidden channels to see if they have the flag. We can send a GET request to the endpoint `https://discord.com/api/v9/guilds/1212804912321265684/channels` which returns a list of channels in our discord server. There is a hidden channel that says that the "last part of the flag is a snowflake related to this channel". Looking at the only snowflakes of the channel, there is `guild_id`, `parent_id`, `id`, and `last_message_id`. `last_message_id` is the only unique type of snowflake available so that must be it.

Next we check for other hidden things. For example, roles. Send another GET request to a similar endpoint `https://discord.com/api/v9/guilds/1212804912321265684/roles` for the list of roles. Immediately, we see the first part of our flag as one of the role names.

Maybe there's something hidden in the server description? Another GET request to `https://discord.com/api/v9/guilds/1212804912321265684` shows a server description, "4 parts". Well, we have 2 out of 4 parts now.

As we look through the response in the request, we see that the role name is here, but there is also an extra emoji than when we looked at the GUI. Turns out it had a permission overwrite only displaying the emoji to people who had a certain role which is why we can't see it on our client. The emoji gives us our second part.

We have one part left. Recalling the hidden channels, we remember that there is a hidden voice channel. We also noticed that one of the features in the server request said soundboard. After researching quite a bit, we find that there is no endpoint to getting a list of soundboards. Instead we join a voice channel in another server to find 6 soundboard sounds from b02lers, each named as different meme sounds. We preview each one and find that "brrrr" holds a weird sound. We check the networks tab and find the request to get the sound and we can download it, upload it to VLC, and convert to spectrogram revealing the third and final flag. You can also download it by right clicking the sound (if you have nitro or a spoofer).