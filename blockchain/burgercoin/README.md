# Writeup for burgercoin by CygnusX

We can see that we need to somehow get the owner's balance to be zero. But there is no way for us to make an uncontrolled account lose burgercoins... or is there?

The first thing to note, is that the total supply of the contract is a signed integer. This means that the total supply can go negative and that variable is essentially useless. 

We can also notice that we can create as many new accounts as we want, and mint them burger coins, then transfer those burger coins to any address. 

This lets us take over ownership of the burger coin contract.

We can just change the owner to some random address with zero burgercoins, and the contract will think we drained the owner's balance. Thus giving us the flag. An example solve script and attack contract are given in ./solve.