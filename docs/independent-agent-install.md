# Installing an independent SentinelX agent instance

The normal SentinelX installation uses `/opt/sentinelx-cloud-core`,
`/etc/sentinelx/config.yaml`, `/etc/sentinelx/identity.json`, and the
`sentinelx-core.service` unit. Do not overwrite those paths when testing a
second agent on the same host.

`./scripts/install-agent.sh` can install this repository as a separate
systemd instance with its own installation prefix, config, identity, service
name, and Unix service account.

Example for a test agent:

```bash
sudo bash ./scripts/install-agent.sh \
  --prefix /opt/sentinelx-crypto \
  --config /etc/sentinelx-crypto/config.yaml \
  --identity /etc/sentinelx-crypto/identity.json \
  --service sentinelx-crypto \
  --user sentinelx-crypto \
  --group sentinelx-crypto
```

The installer creates the service account/group if needed, creates a Python
virtualenv below the installation prefix, installs the checkout into that
virtualenv, and writes an independent systemd unit. It does **not** enable or
start the service unless `--enable` or `--start` is supplied.

For the VM 110 E2E experiment, keep the existing `sentinelx-core.service`
running as the emergency/control channel until the experimental agent has
passed all tests. Do not reuse the production agent's `identity.json` for the
second instance; it should receive a separate identity/enrollment.

The crypto agent's private keys are likewise separate from the ordinary agent
configuration. Grant the experimental service account only the specific key
files it needs after the encrypted command/response implementation is ready.

## Verification before start

```bash
sudo systemctl daemon-reload
sudo systemctl status sentinelx-core --no-pager
sudo systemctl cat sentinelx-crypto
```

Only after the configuration and separate identity have been checked should
the test instance be enabled or started:

```bash
sudo systemctl enable --now sentinelx-crypto
```

Never stop or replace `sentinelx-core` as part of the experimental install.
