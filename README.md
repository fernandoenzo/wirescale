# Wirescale

[![PyPI](https://img.shields.io/pypi/v/wirescale?label=latest)](https://pypi.org/project/wirescale/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/wirescale)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/wirescale)
![PyPI - Status](https://img.shields.io/pypi/status/wirescale)

![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/fernandoenzo/wirescale)
[![GitHub last commit](https://img.shields.io/github/last-commit/fernandoenzo/wirescale)](https://github.com/fernandoenzo/wirescale)

Welcome to Wirescale, a revolutionary tool that transforms the way you use VPNs. Built for Linux, Wirescale leverages the power of WireGuard’s kernel-level
performance
and Tailscale’s unbeatable udp hole-punching capabilities to create a robust, fully customizable mesh VPN experience.

## Table of contents

<!--ts-->

* [Installation](#installation)
    * [Requirements](#requirements-for-installing-the-program)
    * [Install](#install)
    * [Upgrade](#upgrade)
    * [Uninstall](#uninstall)
* [Use case](#use-case)
    * [Architecture](#architecture)
    * [Upgrading a connection](#upgrading-a-connection)
    * [Exit Nodes](#exit-nodes)
        * [Example usage](#example-usage)
        * [Considerations about `fwmarks` and `ip rules`](#considerations-about-fwmarks-and-ip-rules)
    * [The `autoremove-%i` unit](#the-autoremove-i-unit)
    * [The `[Wirescale]` section](#the-wirescale-section)
* [Packaging](#packaging)
    * [Python Wheel](#python-wheel)
    * [Standalone executable binary](#standalone-executable-binary)
* [Contributing](#contributing)
* [License](#license)

<!--te-->

## Installation

### Requirements for installing the program

- `gcc >= 12.2`
- `pipx >= 1.1.0`
- `python >= 3.11`
- `python-dev >= 3.11`

### Requirements for regular use

- `ping`
- `python >= 3.11`
- `systemd >= 252`
- `tailscale >= 1.60`
- `wireguard-tools`

### Install

The installation is a three-step dance involving the program itself, the `systemd` service `wirescaled.service`, and the socket `wirescaled.socket`, also
managed by `systemd`. Here’s the quickest way to get everything up and running:

```commandline
~ $ curl -fsSL https://raw.githubusercontent.com/fernandoenzo/wirescale/master/install.sh | sudo sh
```

This magic command will download Wirescale, place it in a user-friendly folder via `pipx`, and create symbolic links to the systemd units
in `/etc/systemd/system`. Easy peasy!

### Upgrade

Once Wirescale is installed, keeping it up-to-date is a piece of cake with `pipx`.

Starting from version `1.5` of `pipx` you can simply do:

```commandline
~ $ sudo pipx upgrade --global wirescale
```

For `pipx` versions lower than `1.5`, you’ll need to specify the folders where Wirescale resides:

```commandline
~ $ sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx upgrade wirescale
```

This command tells `pipx` exactly where to find `wirescale`, ensuring your upgrades are smooth and hassle-free. Now, you’re always equipped with the latest and
greatest version of Wirescale!

Don't forget to reload and restart the `wirescaled.service` unit once the upgrade is completed:

```commandline
~ $ sudo systemctl daemon-reload
~ $ sudo systemctl restart wirescaled.socket wirescaled.service
```

### Uninstall

Need to uninstall? No problem! This script will make Wirescale disappear without a trace:

```commandline
~ $ curl -fsSL https://raw.githubusercontent.com/fernandoenzo/wirescale/master/uninstall.sh | sudo sh
```

## Use case

Tailscale has become the go-to solution for establishing point-to-point connections, effortlessly traversing NATs and interconnecting endpoints. However, it
relies on a custom version of `wireguard-go` reimplemented by Tailscale, instead of the usual `wireguard`. This approach has its limitations - you can’t
customize any connection parameters, and it doesn’t operate at the kernel level, which leads to suboptimal performance.

Beyond that, I struggle with a few things about Tailscale, such as the fact that it is not completely open source (coordination server is not, and I am forced
to use a sketchy alternative like `headscale`) and it doesn't utilize the official WireGuard implementation like other projects such as Netmaker or Netbird.
These projects, however, come with their own set of issues, like the complexity of their configuration process, unlike Tailscale, which is straightforward and
quick.

While this might be acceptable for most users who aren’t concerned about performance or software freedom, I’ve always found it regrettable that Tailscale is not
completely open source, even though [they like to falsely promote themselves as such](https://tailscale.com/opensource). Additionally, the fact that it also
doesn't offer the same level of customization as the Wireguard configuration files bothered me. This is particularly relevant for advanced use cases, which is
what this tool was designed for.

Wirescale takes a pre-existing Tailscale network and forces a hole punching between two machines. Using the port data obtained from the hole punching, Wirescale
sets up a pure WireGuard connection between the two machines. But here’s the kicker - it uses user-defined WireGuard configuration files, allowing for 100%
customization of every parameter. From pre/post scripts and network IPs to AllowedIPs and more, you have complete control over your WireGuard configuration.

In essence, Wirescale allows you to upgrade your connection between two machines on a Tailscale network to a pure WireGuard connection. And the best part? It
operates independently of the Tailscale process.

### Architecture

Wirescale is a multitasking champ! It runs as a UNIX and WebSockets server from the `systemd` unit, listening on both the local socket opened in
the `wirescaled.socket` unit and the Tailscale IP of the machine running it. This means it can handle both remote requests for connection upgrades and local
requests for a directed upgrade to another peer.

Curious about the different modes of operation? Run `wirescale -h` to see them:

- `daemon` mode is launched from the `systemd` unit. Configure it with the options that suit your needs (`wirescale daemon -h` will list them all).
- `upgrade` option is where the magic happens, and we’ll dive deeper into this shortly.
- `recover`  option will attempt to re-establish the connection for an interface that has been detected as down, ensuring it reconnects with its peer.
  This option is for internal use only.
- `exit-node` option will allow you to route all your outgoing traffic through a peer acting as an exit node.
- `down` option is the easiest way to take down a network interface raised with Wirescale.

### Upgrading a connection

Let’s imagine you have a Tailscale network with two machines, which we’ll call `alice` (`100.64.0.1`) and `bob` (`100.64.0.2`). These names, `alice` and `bob`,
are how Tailscale identifies the machines when you run `tailscale status` and list all the devices, like this:

```commandline
~ $ tailscale status
fd7a:115c:a1e0::1 alice    user     linux   -
fd7a:115c:a1e0::2 bob      user     linux   -
```

Now, you want to take it up a notch. You want a pure, unadulterated point-to-point WireGuard connection between `alice` and `bob`. It’s like setting up a
private line in a world of party lines. How do you do it? Simple. You create WireGuard configuration files in `/etc/wirescale/`. For each peer you want to
connect to, you’ll need to define a file with its name. So, on the `alice` machine, you’ll define an `/etc/wirescale/bob.conf`, and on the `bob` machine, you’ll
define an `/etc/wirescale/alice.conf`.

These configuration files are standard WireGuard files, with an optional additional `[Wirescale]` section, as shown in the following complete example:

```
[Interface]
Address = 192.168.3.1
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
AllowedIPs = 192.168.3.0/24

[Wirescale]
iptables-forward = True
iptables-masquerade = True
interface = custom_name
suffix = true
recover-tries = 2
recreate-tries = 1
```

Notice the abscence of `Endpoint` and `ListenPort` fields? That’s `wirescale` working its magic, automatically filling these in based on what
it captures from `tailscale`.

With Wirescale, you’re in control. You can go from a zero-trust configuration to a fully self-managed one. That means you don’t need to use a complete
configuration file like in the previous example. The only essential fields you need to define are `Address` and `AllowedIPs`, as shown in the following example:

```
[Interface]
Address = 192.168.3.1

[Peer]
AllowedIPs = 192.168.3.0/24
```

If you opt for this, `wirescale` will automatically negotiate the public key and the pre-shared key for each connection established between peers. You can even
asymmetrically configure the peers, specifying the `PrivateKey` field in one of them if you want it to always use the same one, and not in the other. In any
case, any compatibility conflict between the peers’ configurations will be appropriately warned by `wirescale`. It’s your network, your rules!

We’ll focus on the options in the `[Wirescale]` section later. All you need to know now is that these options are also explained in `wirescale upgrade -h`, and
that an option set by command line always takes precedence when `wirescale` acts as a client, as is the case here, over one set in a configuration file.

Once you’re happy with your setup, just launch the following command on one of the nodes, say, `alice`:

```commandline
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

In this example, `defe22` is a randomly generated unique uid to easily follow the process trace when we execute the
command `journalctl -f -u wirescaled.service`.

You can see your brand new P2P WireGuard connection working with:

```commandline
~ $ wg show bob
```

and you'll get an output like this:

```
interface: bob
  public key: Jagl9ZKgJpnatDNH+2Z1WQC13dVMSyLyAh0iU98qrRc=
  private key: (hidden)
  listening port: 39216

peer: 9FFbjKGCbGWDIyDB6ZW4D/ENgxqBSBIiBfkBYCCSvjI=
  preshared key: (hidden)
  endpoint: 70.125.39.64:38741
  allowed ips: 192.168.3.0/24
  latest handshake: 5 seconds ago
  transfer: 308.02 KiB received, 368.59 KiB sent
  persistent keepalive: every 10 seconds
```

It’s worth noting that the configuration files generated by `wirescale` are located in `/run/wirescale/`, so you can check the transparency of the process.

Just a quick heads-up! If you stumble upon an "unexpected" `Endpoint` (like seeing a private IP when you’re expecting a public one due to an additional VPN
between your machine and the peer), don’t be alarmed! You might have run into a [known issue](https://github.com/tailscale/tailscale/issues/1552) that Tailscale
has steadfastly refused to fix. However, I’ve independently addressed this in my [TailGate](https://github.com/fernandoenzo/tailgate/) project, which you'll
definitely find worth exploring.

### Exit Nodes

The `exit-node` option allows you to route all outgoing traffic through a peer that acts as an exit node. This setup is ideal when you want to send all your
traffic to the internet through another machine in your WireGuard network. When using this option, `wirescale` will ensure that your traffic is intelligently
routed, meaning that local traffic to other nodes, be it in Wirescale or Tailscale networks, will not be affected. Only internet-bound traffic is forwarded
through the exit node.

#### Example usage:

Continuing with the previous example, to enable an already set up interface `bob` as an exit node, simply run the following command:

```commandline
~ $ sudo wirescale exit-node bob
```

If successful, you will see the following output:

```commandline
Interface 'bob' has been enabled as an exit node ✅
```

You may ask at any time which interface is the current exit node:

```commandline
~ $ wirescale exit-node --status
bob
```

To stop routing traffic through the exit node and revert to the previous configuration, run:

```commandline
~ $ sudo wirescale exit-node --stop
Interface 'bob' has been deactivated as an exit node ❌
```

If you try to set a new exit node while one is already active, the current exit node will be automatically deactivated, and the new one will take over:

```commandline
~ $ sudo wirescale exit-node alice
Interface 'bob' has been deactivated as an exit node ❌
Interface 'alice' has been enabled as an exit node ✅
```

For the exit node to function properly, the chosen peer must have both the `iptables-masquerade` and `iptables-forward` options enabled. Otherwise, the traffic
forwarding to the internet might not work as expected or even at all.

#### Considerations about `fwmarks` and `ip rules`

If you plan to use the `fwmark` option in your WireGuard configuration files or are thinking about tinkering with the `ip rules` on your machine, there are
some reserved values you need to keep in mind to avoid conflicts. Below is a list of the key values that both Wirescale (only while an `exit-node` is active)
and Tailscale use:

1. Tailscale filters out any fwmark matching `0x80000/0xff0000`
2. Wirescale filters out the fwmarks `0xa08d037b` and `0xa08d037c`
3. Tailscale uses the IP rule IDs `5210`, `5230`, `5250`, and `5270` for its own rules
4. Wirescale uses IP rule IDs between `5500` and `6000` as needed
5. Wirescale sets a routing table with ID `0xA08D037A`

So, if you're planning to mess around with IP rules or fwmarks, make sure you don’t break anything based on what we've just listed.

### The `autoremove-%i` unit

In Wireguard’s configuration files, `%i` is a placeholder that gets replaced with the network interface name. If you look at the second-to-last line of the
previous log, you’ll notice that a systemd unit called `autoremove-bob.service` was started right after the tunnel was set up. This unit has only one job: to
either restore the connection if it drops or to remove the network interface if the connection can’t be restored.

A connection made with Wirescale is a pure P2P link between machines. This connection can drop for a variety of reasons, ranging from a machine losing its
internet connection, to a router unilaterally closing the open connection, or even the local Linux firewall deciding it’s done with it.
The`autoremove-bob.service` unit is designed to attempt to restore the connection based on the `recover-tries` option in the WireGuard configuration file (or
the`--recover-tries` command-line option when running `wirescale upgrade`). If the connection can’t be restored after the specified number of attempts, the
network interface will be removed and a new connection will be attempted from scratch, based on the `recreate-tries` parameter or the `--recreate-tries`
command-line option.

It’s crucial to note that both the `recover` and `upgrade` options require Tailscale to be operational to perform a new hole punching with the other peer. This
is essential for establishing a direct connection between the two machines. However, if it’s not possible to find an Endpoint to the other peer, and the traffic
is being relayed through a DERP server, `wirescale` will NOT set up a tunnel between the machines. This ensures that Wirescale only establishes connections when
a direct peer-to-peer link is possible

Moreover, this systemd unit will actively try to keep the routers from closing the connection by sending small periodic packets. Therefore, it’s mandatory to
have `ping` available on your system.

### The `[Wirescale]` section

The `[Wirescale]` section of config files seen before is entirely optional, and accepts the following fields:

- `interface` The network interface name that WireGuard will set up for this peer. Defaults to the peer name.
- `iptables-accept` Can be `true` or `false`. If set to `true`, iptables rules will be added to allow incoming traffic through the new network interface.
  Useful when the default INPUT policy is set to DROP. This should not be necessary in most cases. Defaults to `false`.
- `iptables-forward` Can be `true` or `false`. If set to `true`, iptables rules will be added to enable forwarding of traffic through the new network interface.
  Defaults to `false`.
- `iptables-masquerade` Can be `true` or `false`. If set to `true`, iptables rules will be added to mark and masquerade traffic routed through the new network
  interface. Use this to enable NAT for outgoing packets. Defaults to `false`.
- `recover-tries` The number of automatic recovery attempts if the connection drops before the network interface is brought down. Negative values indicate
  unlimited attempts. Defaults to 3 tries.
- `recreate-tries` The number of attempts to create a new tunnel if the network interface was brought down after failing to recover it. Negative values
  indicate unlimited retries. Defaults to 0 tries.
- `suffix` Can be `true` or `false`. When set to `true`, a numeric suffix is appended to new interfaces that share names with existing ones. This suffix can be
  referenced in the configuration file as `%s`, mirroring the substitution process that `%i` undergoes for the interface name. If no suffix is added, `%s` is
  set to 0. Defaults to `false`.

As mentioned earlier, any of these fields can be optionally configured when running the `wirescale upgrade` command. It's important to note that if Wirescale
operates in a client role, command-line arguments will override settings specified in the configuration file.

Additionally, when Wirescale functions as a server through the `wirescale daemon` command specified in the `systemd` unit, the situation changes. In this
scenario, preferences set via the configuration file will supersede those provided through command-line arguments.

## Packaging

This section walks you through the packaging process. However, it’s important to note that you typically won’t need to worry about this. The recommended way to
upgrade the program is through `pipx`, as explained earlier.

### Python Wheel

To generate the program wheel, available at PyPi, install first `autopackage` with `pipx`:

```commandline
~ $ pipx install autopackage
```

Once `autopackage` is installed, run the following command::

```commandline
~ $ autopackage -s setup.py
```

This will generate the `whl` package and place it in the `/releases` directory.

### Standalone executable binary

In addition to the wheel, you can also create a standalone binary of the program. This binary can run independently, without requiring a Python interpreter or
any other library dependencies on your machine.

To build this binary, we’ll use a prepared script that leverages Docker:

```commandline
~ $ ./bundle/generate
```

Running this command will generate an executable in the `/dist` directory. You can move this executable to `/usr/local/bin`, and it will operate independently.

One of the key advantages of this standalone binary is its compatibility. It’s designed to work across different Linux distributions, making the program
versatile and user-friendly.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

![PyPI - License](https://img.shields.io/pypi/l/wirescale)

This program is licensed under the
[GNU Affero General Public License v3 or later (AGPLv3+)](https://choosealicense.com/licenses/agpl-3.0/)
