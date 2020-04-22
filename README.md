# Proof of Latency
Proof of latency is a novel algorithm that creates a public proof of latency between two network connected peers.
Example use cases include things like dynamic routing in a DHT routed P2P network, or it could possibly be used as a base for a programmatic proof of work algorithm.
The enabling technology for this is a verifiable delay function.

## Prerequisites
Currently requires Linux to run with GNU Multiple Precision Library.

To install it on Debian/Ubuntu:
```bash
sudo apt-get install -y libgmp-dev
```

...or on Red Hat based distros, such as Arch, Fedora, CentOS:
```bash
sudo dnf -y install gmp-devel
```

...and you should be good to go!

