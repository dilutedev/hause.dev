# hause

A personal server stack: a static landing page plus a small passkey-protected admin panel for watching and quitting processes.

- `site/`: the static landing page, served by Caddy.
- `admin/`: the admin panel. It's a single Go binary: a live process list where you can select one or more processes, see their executable path and listening ports, and quit them, with passkey-only sign-in.
- `deploy/`: the systemd unit, sudo rule, Caddy site and install script.

## Deploy

On the server, copy the example settings and fill in your own email and domains:

```sh
cp deploy/hause.env.example deploy/hause.env
```

- `HAUSE_ACME_EMAIL`: the contact email Caddy gives Let's Encrypt for certificates.
- `HAUSE_SITE_DOMAIN`: the domain for the landing page, such as `example.com`.
- `HAUSE_ADMIN_DOMAIN`: the domain for the admin panel, such as `admin.example.com`.

`deploy/hause.env` is ignored by git, so your email and domains stay out of the repository. Then run:

```sh
./deploy/install.sh
```

The script builds the binary and does the rest:

- installs the binary to `/usr/local/bin/hause-admin`;
- runs the binary as the `hause-admin` system user, whose only sudo rights are `/usr/bin/kill`, `/usr/bin/ss -tulpnH` and `readlink` on `/proc/<pid>/exe`;
- copies the landing page into place and reloads Caddy.

## Devices

- **First device.** On the first start, the service logs a one-time setup link:

  ```sh
  journalctl -u hause-admin | grep setup
  ```

- **Every device after that.** The new device opens the panel, chooses **Request access** and shows a code. You enter that code under **Devices** on a device that's already signed in.

- **Locked out.** If you lose every device, SSH in and print a new setup link, which adds one device:

  ```sh
  sudo -u hause-admin hause-admin setup-link
  ```

## Safety rails

- Quitting processes, approving a device and removing a device all require a passkey check from the last 10 minutes.
- These processes are shown but can't be stopped from the panel: init, systemd services, sshd, tailscaled, caddy, dockerd/containerd, dbus, kernel threads and the panel itself.
- Listening ports and the executable path are read with `sudo ss` and `sudo readlink` only when you open a process, so the journal isn't flooded with sudo entries.
- Every sign-in, device change and signal sent goes to the journal (`journalctl -u hause-admin`).
