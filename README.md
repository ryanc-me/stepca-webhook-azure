# Azure webhook for Step-CA

This webhook fetches and returns the Object IDs for all groups that the user belongs to.

## Use Case

This is used at Wedoo to facilitate per-server access control.

Each of our servers has a dedicated Azure group (e.g., `server-exampleclient-prod`).
The server is then configured so that group ID is added to sshd's
`AuthorizedPrincipalsFile`. Thus, if a user presents a cert where the SSH-Cert
contains that group `server-exampleclient-prod`, then they will be granted access.

## Why is This Necessary?

Because Azure will only return up-to 200 groups in the JWT. If the user belongs to more groups, then the `groups` key is *totally omitted* from the JWT.

This poses an issue as group counts increase - one day, some users may find their SSH-Certs are invalid.

## Setup

### Prerequisites

 * [*Provisioner Remote Management*](https://smallstep.com/docs/step-ca/provisioners/#remote-provisioner-management) must be enabled. Note that this means provisioners are stored in the DB and managed via CLI, rather than via config files.

### Azure Application

 1. Visit the [App registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps) blade
 2. Click *New registration*
 3. Single-tenant mode is fine, and Redirect URI is not required
 4. Within the application, visit `API permissions` (on the left)
 5. Add the following:
    * Microsoft Graph -> Application permissions -> `User.Read.All`
    * Microsoft Graph -> Application permissions -> `GroupMember.Read.All`
 6. Make sure to *Grant admin consent*
 7. Back at the application homepage, click *Client credentials*, and create some credentials. Make sure to note the secret

### Webhook Config

Now, we can take some data from the Azure application to fill out the env file.

 1. Make a copy of the `.env` file somwhere
 2. Fill in the info from Azure:
    * `AZURE_TENANT_ID` = *Directory (tenant) ID*
    * `AZURE_CLIENT_ID` = *Application (client) ID*
    * `AZURE_CLIENT_SECRET` = The secret you noted above

### Configure mTLS

StepCA requires that webhooks are served via `https`, and that the certificate is valid. It makes sense to use a Step CA-issued cert for this purpose.

See the `.env.example` for more info.

Note that mTLS will not work when a reverse proxy (e.g., Nginx) is involved, so in that case, disable `TLS_REQUIRE_CLIENT_CERT`.

### Running with `docker compose`

It's recommended to run this via `docker compose`. Below is a quick template you may wish to use:

```yaml
step-ca-webhooks:
container_name: step-ca-webhooks
build:
    context: ./stepca-webhook-azure
env_file:
    - "./configs/step-ca-webhooks/.env"
volumes:
    - "./certs:/app/certs:ro"
networks:
    - internal
ports:
    - 5000:5000
```

### Adding the Webhook

Now, we can add the webhook to Step-CA. See [Webhooks](https://smallstep.com/docs/step-ca/webhooks/) for more info.

Something like this should work:
```bash
# note: make sure to replace "MyProvisioner" with your provisioner name
step ca provisioner webhook add MyProvisioner azureGroups --url "https://step-ca-webhooks:5000/ssh/enrich"
```

This command will print out the webhook ID/secret. Those need to be copied into the `.env` file as `STEPCA_WEBHOOK_ID` and `STEPCA_WEBHOOK_SECRET` respectively.

### Template Config

Finally, we can set up a template for the provisioner. See [SSH Templates](https://smallstep.com/docs/step-ca/templates/#ssh-templates) for more info.

An example:
```yaml
{
	"type": "{{ .Type }}",
	"keyId": "{{ .KeyID }}",
	"principals": {{ toJson .Webhooks.azureGroups.azure_group_ids }},
	"extensions": {{ toJson .Extensions }},
	"criticalOptions": {{ toJson .CriticalOptions }}
}
```