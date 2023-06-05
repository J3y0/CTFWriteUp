# Description

```
Alors que votre esprit se laissait aller à différentes considérations, une scène étrange capta votre attention. Un vieil homme, agitant frénétiquement ses membres sur une chaise, arborait une expression anxieuse. Emu, vous vous enquîtes de son état, et il se confia à vous, révélant sa profession d'antiquaire et la perte du mot de passe pour accéder à l'un de ses coffres-forts, abritant des antiquités de valeur.

D'un cœur compatissant, vous décidâtes de l'accompagner dans sa boutique pour tenter de retrouver le précieux sésame. Le vieil homme mentionna alors l'existence d'un mémorandum, rédigé il y a de cela quelques années, qui pourrait lui être d'une grande aide en pareille circonstance. Mais, en proie à une certaine confusion, il ne savait plus comment en faire usage. Ainsi vous chargea-t-il de la mission de trouver le mot de passe grâce à ce mémorandum. En guise de remerciement, il vous offrirait la magnifique peau de chagrin ornementant le mur.
```

# Solve

I try this python script to decode what looks like hexadecimal into ascii.

```python
import binascii

with open("./memorandum.txt", "r") as f:
	output = open("./out.bytes", "wb")
	output.write(binascii.unhexlify(f.read()))
	output.close()
```

Once this is done, I quickly look how the output looks like with the command:
```bash
hexdump -C out.bytes
```

and I saw it was the idea as there were bits of understandable ASCII.

So I did a `strings` on the file to have a quick overview of what are those bits.

I found `/ipfs/bafybeia5g2umnaq5x5bt5drt2jodpsvfiauv5mowjv6mu7q5tmqufmo47i/metadata.json` which looks very interesting.

After some research on what IPFS is, I visited this URL: https://cloudflare-ipfs.com/ipfs/bafybeia5g2umnaq5x5bt5drt2jodpsvfiauv5mowjv6mu7q5tmqufmo47i/metadata.json.

Alright, we are given a second IPFS endpoint ! We are on the right track !

I visited : https://cloudflare-ipfs.com/ipfs/bafybeic6ea7qi5ctdp6s6msddd7hwuic3boumwknrirlakftr2yrgnfiga/mystere.png

On the mysterious image, was readable: `0x96C962235F42C687bC9354eDac6Dfa6EdE73C188` and `Sepolia`.

Sepolia is a test network on `etherscan` and the other string is a contract. One can found back the contract on `etherscan`. Once this is done, we can read the variables of the contract, there is one particularly interesting: `secretString`.

We can read its value, which is the flag !

Flag: *404CTF{M3M3_P45_13_73MP5_D3_53CH4UFF3r_QU3_C357_D3J4_F1N1!}*
