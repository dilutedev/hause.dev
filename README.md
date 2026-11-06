# hause.dev

- `site/`: the static landing page at https://hause.dev, served by Caddy from `/var/www/hause`.
- `admin/`: the server admin panel at https://su.hause.dev. It's a single Go binary: a live process list where you can quit processes, with passkey-only sign-in.
- `deploy/`: the systemd unit, sudo rule, Caddy site and install script.

## Deploy

On the server:

```sh
./deploy/install.sh
```

The script builds the binary and does the rest:

- installs the binary to `/usr/local/bin/hause-admin`;
- runs the binary as the `hause-admin` system user, whose only sudo right is `/usr/bin/kill`;
- copies the landing page into place and reloads Caddy.

## Devices

- **First device.** On the first start, the service logs a one-time setup link:

  ```sh
  journalctl -u hause-admin | grep setup
  ```

- **Every device after that.** The new device opens https://su.hause.dev, chooses **Request access** and shows a code. You enter that code under **Devices** on a device that's already signed in.

- **Locked out.** If you lose every device, SSH in and print a new setup link, which adds one device:

  ```sh
  sudo -u hause-admin hause-admin setup-link
  ```

## Safety rails

- Quitting a process, approving a device and removing a device all require a passkey check from the last 10 minutes.
- These processes are shown but can't be stopped from the panel: init, systemd services, sshd, tailscaled, caddy, dockerd/containerd, dbus, kernel threads and the panel itself.
- Every sign-in, device change and signal sent goes to the journal (`journalctl -u hause-admin`).
