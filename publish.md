# Publishing Epheme packages

Packages: `@epheme/core`, `@epheme/plugin-sdk`  
Registry: `https://npm.sillygooseia.com` (private Verdaccio on k3s)

---

## Why auth breaks

Verdaccio issues **short-lived JWT tokens**, not permanent API keys. Every time the
Verdaccio pod restarts (deploy, rollout, node reboot) all previously issued tokens are
invalidated. The token stored in your global `~/.npmrc` becomes stale silently — npm
will report `E401` or `E403` without a clear expiry message.

**Root cause:** Verdaccio uses a symmetric JWT secret that is pod-scoped unless you
pin it via `SECRET` env var in the Helm values. We have not done this yet (see TODO
at the bottom).

---

## Step 1 — Get a fresh token (do this every time auth fails)

**Important:** Use `ConvertTo-Json` for the request body — manual JSON string escaping can fail.

```powershell
# From anywhere — reads the admin password from secrets
$j = Get-Content C:\Users\ben\source\repos\sillygooseia-corp\secrets\npm-registry.json | ConvertFrom-Json
$a = ($j.users | Where-Object username -eq 'admin')

# Call Verdaccio's CouchDB login endpoint — returns a fresh JWT
# Use PowerShell object → ConvertTo-Json for proper formatting
$body = @{
    name = 'admin'
    password = $a.password
    email = 'admin@sillygooseia.com'
    type = 'user'
} | ConvertTo-Json -Compress

$resp = Invoke-RestMethod -Uri "https://npm.sillygooseia.com/-/user/org.couchdb.user:admin" -Method PUT -ContentType "application/json" -Body $body
$token = $resp.token
Write-Host "Token: $token"

# Write to global .npmrc
npm config set "//npm.sillygooseia.com/:_authToken" $token

# Verify
npm whoami --registry https://npm.sillygooseia.com
# expected output: admin
```

> **Note:** `npm login` does NOT work for Verdaccio in non-interactive terminals —
> it hangs waiting for a password prompt even when piped. Always use the REST API
> approach above.

---

## Step 2 — Bump versions (if publishing new content)

```powershell
# Bump @epheme/core
Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme\packages\core
npm version patch   # or minor / major

# Bump @epheme/plugin-sdk
Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme\packages\plugin-sdk
npm version patch
```

---

## Step 3 — Build

```powershell
# core (compiles browser/ TypeScript to dist/)
Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme\packages\core
npm run build

# plugin-sdk (tsc)
Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme\packages\plugin-sdk
npm run build
```

`prepublishOnly` also runs `build` automatically, so this step is optional — but
running it manually first lets you catch TypeScript errors before the publish attempt.

---

## Step 4 — Publish

```powershell
Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme\packages\core
npm publish --registry https://npm.sillygooseia.com

Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme\packages\plugin-sdk
npm publish --registry https://npm.sillygooseia.com
```

### Verify the published packages are live

```powershell
npm view @epheme/core --registry https://npm.sillygooseia.com
npm view @epheme/plugin-sdk --registry https://npm.sillygooseia.com
```

---

## Step 5 — Tag + push git

```powershell
Set-Location C:\Users\ben\source\repos\sillygooseia-corp\epheme

# Tag both packages at current HEAD (adjust versions as needed)
git tag core-v0.1.2
git tag plugin-sdk-v0.1.0
git push origin --tags
git push
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `E401 need auth` | Stale token in `~/.npmrc` | Re-run Step 1 |
| `E403 user admin is not allowed to publish` | Stale token **or** Verdaccio config doesn't have `@epheme/*` scope | Re-run Step 1; if still 403, check `kubectl exec ... cat /verdaccio/conf/config.yaml` has `'@epheme/*': publish: $authenticated` |
| `npm login` hangs | Verdaccio requires an HTTP PUT, not interactive login | Use the `Invoke-RestMethod` approach in Step 1 — never `npm login` |
| `E404` on `npm view` after publish | Verdaccio storage path wrong or pod not running | `kubectl get pods -n npm-registry` then check logs |
| Token valid but `npm whoami` says `ENOWORKSPACES` | Running from inside a workspace-root directory | `Set-Location $env:TEMP` then retry `npm whoami` |

---

## Redeploy Verdaccio (when k8s chart changes)

```powershell
Set-Location C:\Users\ben\source\repos\sillygooseia-corp

helm upgrade npm-registry ./infra/helm/npm-registry `
  -f ./infra/helm/npm-registry/values.yaml `
  -f ./infra/helm/npm-registry/values-prod.yaml `
  -n npm-registry

kubectl rollout status deployment/npm-registry -n npm-registry --timeout=60s
```

After any Helm upgrade or pod restart, you'll need to get a fresh token **only if this
is your first login after enabling the stable secret**. Once you have a token issued
with the stable `VERDACCIO_SECRET` in place, it will last 365 days.

---

## DONE — token expiry problem solved

~~TODO — eliminate the token-expiry problem permanently~~

**COMPLETED**: Added a fixed `VERDACCIO_SECRET` env var to the Verdaccio deployment and
configured JWT expiry to 365 days. Tokens now survive pod restarts.
