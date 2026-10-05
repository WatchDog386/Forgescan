# The laboratory

Three virtual machines on one isolated VirtualBox network. All test attacks stay inside it.

| Machine | Address | Role |
| --- | --- | --- |
| Kali Linux | 192.168.56.10 | Generates authorised test attacks |
| Target server | 192.168.56.20 | A deliberately vulnerable server, with nftables and the response agent |
| AI-NIDR server | 192.168.56.30 | Zeek, Suricata, the backend and the database |

## Rules

- Use a host-only network with no route to the internet. Never attach these machines to a real network while testing.
- Never run a scan, a password attack or a flood against anything outside this network.
- Keep automatic response in dry-run mode until the detections look right.

## Setting up

1. In VirtualBox, create a host-only network `192.168.56.0/24` with its DHCP server switched off.
2. Create the three machines, give each a network adapter on that network, and set the addresses above.
3. On the AI-NIDR server's adapter, set Promiscuous Mode to "Allow All". This lets Zeek see traffic between the other two machines.
4. On the AI-NIDR server, install Zeek and copy `sensor/zeek/local.zeek` into its `site/` folder. Start Zeek on the laboratory interface.
5. Start the backend (see the main README), create a sensor key, and start the collector:
   `python sensor/collector.py --log <zeek logs>/current/conn.log --key <sensor key>`
6. On the target server, follow the steps at the top of `lab/response-agent.sh`.
7. In `.env`, set `FIREWALL_MODE=ssh`, `FIREWALL_HOSTS=responder@192.168.56.20` and `FIREWALL_SSH_KEY` to the private key.

## Labelling traffic for training

Keep a schedule of every test: start time, end time, attacker address and attack type. Windows from the attacker
inside those times get that label; everything else is normal. `ml/train.py` trains on the labelled windows.
