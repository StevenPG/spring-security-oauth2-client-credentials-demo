# Demo

Setup

```bash
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.2.5 start-dev
```

Sign into keycloak on `localhost:8080` with the credentials `admin:admin`.

Create a new client in the master realm with the following settings:

- Client ID: `test`
- Client type: `openid-connect`
- Client authentication: `on`
- Authentication flow: `service account roles`

Override the client secret in application.yaml with the content from Keycloak.

Hit play in Intellij!

Sample Output:

```text

```