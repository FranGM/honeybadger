# honeybadger

Proof of concept of a key management daemon that negotiates IPsec associations without involving IKE. Honeybadger uses SSH internally to perform SA negotiation with other nodes in an attempt to reduce complexity and build a system that's easier to secure. The end goal of this project would be to produce a replacement for `ipsec-tools` (and the `racoon` daemon) that's better suited to today's internet.


Disclaimer: This code is just a proof of concept, and while it works and can be used to negotiate and maintain IPsec SAs between hosts there it's unlikely to be useful in any real world scenario. 
