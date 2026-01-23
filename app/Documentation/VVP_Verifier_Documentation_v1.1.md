## 7. Coding Agent Instructions

These instructions apply to Codex or any automated coding agent.

### Scope Rules

-   Do not modify infrastructure unless explicitly instructed
-   Do not introduce secrets
-   Do not weaken cryptographic verification

### CI/CD Instructions (GitHub → ACR → Azure Container Apps)

The project is deployed by GitHub Actions on every push to the `main` branch.

#### Where the pipeline lives
- Workflow file: `.github/workflows/deploy.yml`
- Trigger: `push` to branch `main`

#### Authentication model (no secrets)
- GitHub Actions authenticates to Azure using **OIDC (workload identity federation)**.
- The workflow requires these GitHub secrets to exist (values are identifiers, not passwords):
  - `AZURE_CLIENT_ID` (Entra app registration client ID)
  - `AZURE_TENANT_ID`
  - `AZURE_SUBSCRIPTION_ID`
  - `AZURE_RG`
  - `AZURE_CONTAINERAPP_NAME`
  - `ACR_NAME`
  - `ACR_LOGIN_SERVER`

Important: do **not** introduce long-lived credentials (passwords, client secrets, admin-enabled ACR accounts). Keep OIDC.

#### What the pipeline does (step-by-step)
1. Checks out the repository.
2. Logs into Azure using `azure/login@v2` with OIDC.
3. Logs into Azure Container Registry (`az acr login`).
4. Builds the Docker image from the repo root (`docker build`).
5. Pushes the image to ACR tagged as the Git commit SHA.
6. Updates the Azure Container App image (`az containerapp update`) to create a new revision.

#### Expected deployment behaviour
- Each successful run creates a **new revision** in Azure Container Apps.
- Traffic routes to the **latest ready revision** (100%) by default.

#### How to verify a deployment (operator checklist)
After a push to `main`:
1. Watch the workflow:
   - `gh run watch --repo andrewbalercnx/vvp-verifier`
2. Confirm a new revision exists:
   - `az containerapp revision list -g VVP -n vvp-verifier -o table`
3. Confirm the deployed image tag is the expected SHA:
   - `az containerapp show -g VVP -n vvp-verifier --query '{image:properties.template.containers[0].image, latestReadyRevisionName:properties.latestReadyRevisionName}' -o json`
4. Confirm runtime health:
   - `curl -sS https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io/healthz`
5. Confirm logs:
   - `az containerapp logs show -g VVP -n vvp-verifier --follow`

#### Common failure modes (and what to do)
- **OIDC login fails (AADSTS700213):** Federated credential `subject` mismatch. Ensure subject matches:
  - `repo:andrewbalercnx/vvp-verifier:ref:refs/heads/main`
- **ACR push fails:** Ensure the OIDC principal has `AcrPush` on the registry scope.
- **Container App image pull fails (UNAUTHORIZED):** Ensure the Container App has:
  - System-assigned managed identity enabled
  - `AcrPull` role on the registry
  - Registry configured with `identity=system` for `rcnxvvpacr.azurecr.io`

#### Rule for coding agents
Any code change that affects runtime behaviour **must** be accompanied by:
- A Git commit with a clear message
- A push to `main` (or a PR merged into `main`)
- A post-deploy verification using the checklist above

### Coding Rules

-   Prefer pure functions
-   All verification steps must log decisions
-   Never silently downgrade verification status
-   All failures must be explicit (`INVALID` or `INDETERMINATE`)

### Logging Rules

-   Every request must have a `request_id`
-   Every claim decision must include reasons
-   Logs must be machine-parsable JSON

### Security Rules

-   Assume hostile input
-   Validate all external data
-   Fail closed, not open
