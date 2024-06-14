# Wirescale

[![PyPI](https://img.shields.io/pypi/v/wirescale?label=latest)](https://pypi.org/project/wirescale/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/wirescale)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/wirescale)
![PyPI - Status](https://img.shields.io/pypi/status/wirescale)

![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/fernandoenzo/wirescale)
[![GitHub last commit](https://img.shields.io/github/last-commit/fernandoenzo/parallel-utils)](https://github.com/fernandoenzo/wirescale)

Welcome to Wirescale, a revolutionary tool that transforms the way you use VPNs. Built for Linux, Wirescale leverages the power of WireGuard’s kernel-level performance 
and Tailscale’s unbeatable udp hole-punching capabilities to create a robust, fully customizable VPN experience.

## Table of contents

<!--ts-->

* [Installation](#installation)
* [Use case](#use-case)
    * [Upgrading a connection](#upgrading-a-connection)
    * [Generate an RSA key pair](#generate-an-rsa-key-pair)
    * [Change a key pair format](#change-a-key-pair-format)
    * [Edit a key passphrase](#edit-a-key-passphrase)
    * [Edit a key comment](#edit-a-key-comment)
    * [Show information about a key](#show-information-about-a-key)
    * [Help](#help)
* [Packaging](#packaging)
    * [Autopackage Portable](#autopackage-portable)
    * [Autopackage Wheel](#autopackage-wheel)
    * [PyInstaller](#pyinstaller)
* [Contributing](#contributing)
* [License](#license)

<!--te-->

## Installation

## Architecture



## Use case

Tailscale has become the go-to solution for establishing point-to-point connections, effortlessly traversing NATs and interconnecting endpoints.
However, it relies on `wireguard-go`, a homegrown implementation by Tailscale. This approach has its limitations - you can’t customize any connection
parameters, and it doesn’t operate at the kernel level, which leads to suboptimal performance.

Beyond that, I struggle with a few things about Tailscale, such as the fact that it is not completely free software (coordination server is not,
and I am forced to use a sketchy alternative like `headscale`) and it doesn't utilize the official WireGuard implementation like other projects such as
Netmaker or Netbird. These projects, however, come with their own set of issues, like the complexity of their configuration process, unlike Tailscale,
which is straightforward and quick.

While this might be acceptable for most users who aren’t concerned about performance or software freedom, I’ve always found it regrettable that Tailscale
doesn’t offer the same level of customization as the Wireguard configuration files do. This is particularly relevant for advanced use cases, which is what
this tool was designed for.

Wirescale takes a pre-existing Tailscale network and forces a hole punching between two machines. Using the port data obtained from the hole punching, Wirescale
sets up a pure WireGuard network between the two machines. But here’s the kicker - it uses user-defined WireGuard configuration files, allowing for 100% customization
of every parameter. From pre/post scripts and network IPs to AllowedIPs and more, you have complete control over your WireGuard configuration.

In essence, Wirescale allows you to upgrade your connection between two machines on a Tailscale network to a pure WireGuard connection. And the best part?
It operates independently of the Tailscale process.

## Upgrading a connection

Let’s imagine you have a Tailscale network with two machines, which we’ll call `alice` (100.64.0.1) and `bob` (100.64.0.2). These names, `alice` and `bob`, are how
Tailscale identifies the machines when you run `tailscale status` and list all the devices.

Suppose you want to establish a pure point-to-point WireGuard connection between these two machines. The first step is to create WireGuard configuration files in
`/etc/wirescale/`. For each node you want to connect to, you’ll need to define a file with its name. So, on the `alice` machine, we’ll define an `/etc/wirescale/bob.conf`,
and on the `bob` machine, we’ll define an `/etc/wirescale/alice.conf`.

These configuration files are standard WireGuard files, with an optional additional `[Wirescale]` section, as shown in the following complete example:

```
[Interface]
Address = 192.0.2.2
PrivateKey = sLBcu1HI/SCOXLwAnuG79DGS1jWDiwk0SyCM40uYuWI=
DNS = 1.1.1.1, 8.8.8.8
Table = off
MTU = 1500
PreUp = /bin/example arg1 arg2 %i %s
PostUp = /bin/example arg1 arg2 %i %s
PreDown = /bin/example arg1 arg2 %i %s
PostDown = /bin/example arg1 arg2 %i %s

[Peer]
PublicKey = QGAYCYJ1Ez7C32wZNw+nI8aBRM8E6OJGKOk0KiCYy0c=
PresharedKey = YFSVOA8Eo0Cj5q9ef0LBA3TudRhKP+3hZMwCljUnKms=
AllowedIPs = 192.0.2.1/24

[Wirescale]
iptables = false
interface = custom_name
suffix = true
recover-tries = 2
recreate-tries = 1
```

As you can see from the example, it’s not necessary to fill in the `Endpoint` or `ListenPort` fields, as `wirescale` will automatically do this
based on what it captures from `tailscale`.

With `wirescale`, you can go from a zero-trust configuration to a fully self-managed one, where the only mandatory fields you must define are `Address` and `AllowedIPs`:

```
[Interface]
Address = 192.0.2.2

[Peer]
AllowedIPs = 192.0.2.1/24
```

If you opt for this, `wirescale` will automatically negotiate the public key and the pre-shared key for each connection established between peers. You can asymmetrically
configure the peers, specifying the `PrivateKey` field in one of them if you want it to always use the same one, and not in the other. In any case, any compatibility conflict
between the peers’ configurations will be appropriately warned by `wirescale`. Customize it to your liking!

We’ll focus on the options in the `[Wirescale]` section later, but I want to emphasize now that these options are also explained in `wirescale upgrade -h`, and that an option
set by command line always takes precedence when wirescale acts as a client, as is the case here, over one set in a configuration file.

For now, once we have it configured to our liking, we just need to launch, on one of the two peers, for example, on `alice`, the following command:

```
~ $ wirescale upgrade bob
```

Then we’ll see how the connection is established, with an output similar to the following if everything goes well:

```
Checking peer 'bob' is correct. This might take some minutes...
Start checking peer 'bob'
Checking that an endpoint is available for peer 'bob' (100.64.0.2)...
Peer 'bob' (100.64.0.2) is reachable
Connecting to local UNIX socket...
Connection to local UNIX socket established
defe22 - Enqueueing upgrade request to peer 'bob' (100.64.0.2)...
defe22 - The upgrade request for the peer 'bob' (100.64.0.2) is the next one in the processing queue
defe22 - The upgrade request for the peer 'bob' (100.64.0.2) has acquired the exclusive semaphore
defe22 - Starting to process the upgrade request for the peer 'bob' (100.64.0.2)
defe22 - Remote peer 'bob' (100.64.0.2) has enqueued our request
defe22 - Remote peer 'bob' (100.64.0.2) has started to process our upgrade request
defe22 - Stopping tailscale...
defe22 - Setting up WireGuard interface 'bob'...
defe22 - Starting tailscale...
defe22 - Launching autoremove subprocess. Running as unit: autoremove-bob.service
defe22 - Success! Now you have a new working P2P connection through interface 'bob'
```

In this example, `defe22` is a randomly generated unique uid to easily follow the process trace when we execute the command 
`journalctl -f -u wirescaled.service`, the systemd unit we initially installed, which acts as a connection server, both locally (through a UNIX socket)
and remotely (through a websockets server).