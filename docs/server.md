# Server

`tbm_server` is the small Told by Mouth server. It does three things and **stores no reviews**:

- **Certificates.** After a real-name identity check and a device attestation, it signs a certificate saying "this device key belongs to this real name". Valid for one year; renewable in the last 30 days (and after expiry).
- **Visit stamps.** It stamps a visit after a device attestation. It only ever sees the `visit_id` (a hash), never the restaurant, location or photo.
- **Revocation list.** It publishes a signed list of revoked people and device keys. Phones download it about once a day.

The database holds only: user ids, a hash of the identity provider's person reference (so one person keeps one user id), issued certificate keys with dates, and revocations. No names, no reviews, no visits.

Everything it signs uses the same encoding and code as the phones (`tbm_core`), so the tests check the server's output with the exact code the apps run.

## API

All bodies are JSON. Binary values (keys, certificates, stamps) are standard base64; certificates, stamps and the revocation list are the CBOR records from `tbm_core`.

| Method and path | Body | Answer |
| --- | --- | --- |
| `GET /healthz` | | `ok` |
| `GET /v1/server-key` | | `server_key_id`, `public_key` (base64), `public_key_hex`. Build this into the apps. |
| `POST /v1/certificates` | `public_key`, `identity {provider, token}`, `attestation {platform, token}` | `certificate`, `user_id` (hex), `expires_at` |
| `POST /v1/certificates/renew` | `certificate`, `signed_at`, `signature` (device key over `Certificate::renew_request_bytes(signed_at)`), `attestation` | same as above |
| `POST /v1/stamps` | `visit_id` (32 bytes), `attestation` | `stamp` (CBOR `Stamp`), `stamp_at` |
| `GET /v1/revocations` | | `revocations` (CBOR `RevocationList`), `issued_at` |
| `POST /v1/admin/revoke` | `user_id` (hex) **or** `device_key` (base64); header `Authorization: Bearer <admin token>` | `revoked`, `at` |

A new certificate for a person who already has one (a new phone) keeps their user id and revokes the old key from that moment. Reviews written with the old phone before the switch stay valid.

Errors come back as `{"error": "..."}` with 400 (bad input), 401 (admin token), 403 (refused), 404, 503 (no identity provider or attestation configured) or 500.

## Identity provider and attestation: still stubs

Which identity check to use depends on the launch country, which is still open (see [decisions.md](decisions.md)). Both checks are traits in `crates/tbm_server/src/providers.rs`:

- `IdentityProvider`: turns the provider's result into a real name and a stable person reference.
- `Attestation`: checks Apple App Attest or Google Play Integrity, bound to the public key (certificates) or the visit id (stamps).

Only **development stubs** exist, enabled with `dev_mode = true`: identity provider `dev` takes the real name as the token, and attestation platform `dev` accepts the token `ok`. **Anyone can claim any name in dev mode.** With `dev_mode = false` (the default), certificate and stamp requests answer 503 until real providers are written. Real App Attest and Play Integrity also need a server-issued challenge; that endpoint comes with them.

## Build

On the server (this OCI box is `aarch64` Ubuntu 22.04; Rust is installed for user `ubuntu` via rustup):

```sh
cd ~/told-by-mouth
cargo test                               # everything
cargo build --release -p tbm_server      # -> target/release/tbm_server
```

## Run by hand (for testing)

```sh
mkdir -p ~/tbm-test && cd ~/tbm-test
cat > tbm-server.toml <<'EOF'
listen = "127.0.0.1:18787"
database = "data/tbm.sqlite"
server_key = "data/server.key"
admin_token_file = "admin.token"
dev_mode = true
EOF
openssl rand -hex 32 > admin.token
~/told-by-mouth/target/release/tbm_server --config tbm-server.toml
curl http://127.0.0.1:18787/healthz
```

`--print-server-key` prints the key id and public key (creating the key if needed) and exits.

## Install as a service

Nothing below has been run on this box yet; these are the steps for Byung to run (they need `sudo`).

```sh
# 1. A system user with no login, and the binary.
sudo useradd --system --home /var/lib/tbm --shell /usr/sbin/nologin tbm
sudo install -m 0755 target/release/tbm_server /usr/local/bin/tbm_server

# 2. Config and admin token. /var/lib/tbm is created by systemd (StateDirectory).
sudo mkdir -p /etc/tbm
sudo cp deploy/tbm-server.toml.example /etc/tbm/tbm-server.toml   # then edit it
openssl rand -hex 32 | sudo tee /etc/tbm/admin.token > /dev/null
sudo chown root:tbm /etc/tbm/admin.token && sudo chmod 0640 /etc/tbm/admin.token

# 3. The service.
sudo cp deploy/tbm-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tbm-server
systemctl status tbm-server
journalctl -u tbm-server -f
```

On first start the server creates `/var/lib/tbm/server.key` (mode 0600). **Back it up somewhere safe**: losing it means every certificate must be reissued and the apps need a new built-in key. It is ignored by git (`*.key`) and must never be committed.

Print the public key for the apps:

```sh
sudo -u tbm /usr/local/bin/tbm_server --config /etc/tbm/tbm-server.toml --print-server-key
```

## Reaching it from phones

Phones refuse plain HTTP (iOS App Transport Security, Android's cleartext default), so the server listens on `127.0.0.1:8787` and HTTPS is done in front of it.

### Option A (recommended): through the existing nginx, no new port

This box already runs nginx with a certbot certificate on ports 80 and 443 (for code-server), and both ports are already open. Paste [`deploy/nginx-tbm.conf`](../deploy/nginx-tbm.conf) inside the `listen 443 ssl` server block in `/etc/nginx/sites-enabled/code-server`, then:

```sh
sudo nginx -t && sudo systemctl reload nginx
curl https://<your-domain>/tbm/healthz
```

The apps then use `https://<your-domain>/tbm/v1/...`. No security list or firewall change is needed. (Note that the same domain also serves code-server; a separate domain or subdomain for the app would be tidier before launch.)

### Option B: a port of its own

If the server should have its own port (say 8443, with TLS in front of it), it has to be opened in **two** places, because OCI blocks traffic both in the cloud network and on the instance:

1. **OCI security list** (cloud side). In the OCI Console: Networking > Virtual Cloud Networks > your VCN > Subnets > the instance's subnet > Security Lists > Default Security List > **Add Ingress Rules**:
   - Source type: CIDR, Source CIDR: `0.0.0.0/0`
   - IP protocol: TCP, Destination port range: `8443`
   - (If the instance uses a Network Security Group instead, add the same rule there.)
2. **Instance firewall** (iptables). OCI's Ubuntu images end the `INPUT` chain with a `REJECT` rule, so a new rule must go **before** it. On this box the REJECT is currently rule 7 of the INPUT chain (check with `sudo iptables -L INPUT --line-numbers` and use its number):

   ```sh
   sudo iptables -I INPUT 7 -p tcp -m state --state NEW -m tcp --dport 8443 -j ACCEPT
   sudo netfilter-persistent save     # keep it after reboot (/etc/iptables/rules.v4)
   ```

   `ufw` is installed but inactive here; don't enable it without adding SSH first, or you can lock yourself out.

Then set `listen` accordingly (or keep it on localhost and put nginx on 8443 with the certificate).

## Admin: revoking someone

```sh
TOKEN=$(sudo cat /etc/tbm/admin.token)
# a person (all their reviews are rejected once phones refresh the list)
curl -X POST https://<your-domain>/tbm/v1/admin/revoke \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"user_id":"<32 hex chars>"}'
# or one device key (reviews written before now stay valid)
  -d '{"device_key":"<base64 key>"}'
```

## Not done yet

- Real identity provider and App Attest / Play Integrity (blocked on the launch country decision).
- A challenge endpoint for attestation, and per-device rate limits on stamps.
- Monitoring and backups of `/var/lib/tbm` (the key and the database).
