# Owlet RTSP Bridge

This self-hosted portal publishes Owlet camera video on your LAN. Sign in with your Owlet account to find your cameras. The portal gets camera credentials from Owlet. The Rust client connects to each camera over UDP. MediaMTX serves the video through RTSP, HLS, and WebRTC.

## Quick start

1. Use a host that can reach the camera on your LAN.
2. Install Docker with the Compose plugin.
3. Set `PUBLIC_HOST` in a root `.env` file to the LAN address or DNS name of the Docker host. For example, use `PUBLIC_HOST=192.0.2.10` with your own host address.
4. Set `RTSP_USER` and `RTSP_PASS` in the same file to protect the streams.
5. Start the portal from the repository root.

   ```sh
   docker compose up
   ```

6. Open `http://<docker-host>:8000` in your browser.
7. Sign in with your Owlet email and password.
8. Enter the **camera's LAN IP** on its card.
9. Select **Save IP**.
10. Set a DHCP reservation for the camera in your router.

Leave the LAN port blank to let the client find it. The first start can take 1 to 3 minutes while the client finds the camera port. The portal remembers the port, and later starts take a few seconds. Use **Edit** to set a known UDP port, rename the camera, or change its publish setting. Use **Sync** to fetch cameras and credentials again. Sync preserves your local settings.

## Watch video

Select the play button on a live camera card to start the WebRTC preview. Use a copy button to get the RTSP, HLS, or WebRTC URL. Use RTSP over TCP in your player.

```text
rtsp://<host>:8554/cam-<lowercase-dsn>
rtsp://<user>:<password>@<host>:8554/cam-<lowercase-dsn>
```

For example, the stream path for `OCC0000000000000` is `cam-occ0000000000000`. HLS and WebRTC players use the same read credentials when you enable stream authentication.

## Configuration

Compose reads the root `.env` file. Run `docker compose up -d` after you change it.

| Variable | Default | Use |
| --- | --- | --- |
| `PUBLIC_HOST` | `localhost` | Host name or IP for viewer URLs and WebRTC. Omit the scheme and port. |
| `RTSP_USER` | Empty | Stream reader name. Set it with the password. |
| `RTSP_PASS` | Empty | Stream reader password. |
| `API_PORT` | `8000` | Portal HTTP port. |
| `RTSP_PORT` | `8554` | RTSP TCP port. |
| `HLS_PORT` | `8888` | HLS HTTP port. |
| `WEBRTC_PORT` | `8889` | WebRTC HTTP port. Media uses UDP port 8189. |
| `DATA_DIR` | `/data` in Docker | Database and logs. Compose mounts the persistent volume here. The local script uses `owlet-rtsp/data/`. |
| `MEDIAMTX_BIN` | `/usr/local/bin/mediamtx` in Docker | MediaMTX executable. Local runs use `mediamtx` on PATH. |
| `MEDIAMTX_API` | `127.0.0.1:9997` | Internal MediaMTX API address. |
| `OWLET_TUTK_BIN` | `owlet-tutk` | Native client executable. |
| `OWLET_API_KEY` | Built-in Firebase client key | Public client key for Owlet sign-in. |
| `OWLET_ACCOUNTS_BASE` | `https://accounts.owletdata.com` | Owlet account service. |
| `OWLET_KMS_BASE` | `https://camera-kms.owletdata.com` | Camera credential service. |
| `OWLET_PACKAGE` | `com.owletcare.sleep` | Android package for Firebase requests. |
| `OWLET_CERT` | Built-in Owlet signing certificate fingerprint | Certificate fingerprint for Firebase requests. |

## Security

Keep the portal and the media ports on a trusted LAN. The default portal uses HTTP. Set both stream read credentials. Anyone who can reach a stream can read it when these fields are empty.

The portal stores account tokens and camera secrets in its data directory. Protect `data/`, its backups, and the root `.env` file. In Docker, the `owlet-data` volume holds the contents of `/data`. The portal exchanges the account password for a token during sign-in.

For a local deployment that uses an existing MediaMTX instance, configure read access on that instance.

**Sign out** ends the browser session. Cameras continue to publish. **Unlink account** stops the streams and removes the account, saved cameras, and portal sessions. **Delete** removes one camera from the portal. A later sync can import it again.

## Limits

The client supports video only. It connects on the LAN only. The camera must be reachable by UDP. Sign-in and camera sync require internet access. Hardware testing covered one Owlet camera model, E96LM72, with firmware 4.2.146.

See the protocol notes in [owlet-tutk/spec/](owlet-tutk/spec/).

This project is not affiliated with Owlet or ThroughTek.

## Licence

AGPL-3.0. See [LICENSE](LICENSE).
