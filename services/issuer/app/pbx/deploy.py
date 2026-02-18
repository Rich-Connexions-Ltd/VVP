"""PBX dialplan deployment via Azure VM run-command.

Deploys generated dialplan XML to the PBX VM by invoking a shell script
through the Azure Compute Management SDK. The script:
1. Backs up the current dialplan
2. Writes the new dialplan
3. Reloads FreeSWITCH configuration
"""

import base64
import logging

from fastapi import HTTPException

from app.config import AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, PBX_VM_NAME

log = logging.getLogger(__name__)


def _get_compute_client():
    """Get Azure Compute Management client and RunCommandInput class.

    Returns a tuple of (client, RunCommandInput) so callers don't need
    a separate import of the Azure SDK models.

    Uses DefaultAzureCredential which supports:
    - Managed Identity (in Azure Container Apps)
    - Azure CLI (local development)
    - Environment variables (CI/CD)
    """
    if not AZURE_SUBSCRIPTION_ID:
        raise HTTPException(
            status_code=503,
            detail="AZURE_SUBSCRIPTION_ID not configured. PBX deployment requires Azure credentials.",
        )

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.compute.models import RunCommandInput

        credential = DefaultAzureCredential()
        client = ComputeManagementClient(credential, AZURE_SUBSCRIPTION_ID)
        return client, RunCommandInput
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Azure SDK not installed. Install azure-identity and azure-mgmt-compute.",
        )


def deploy_dialplan_to_pbx(dialplan_xml: str) -> tuple[bool, str]:
    """Deploy dialplan XML to the PBX VM via Azure run-command.

    Args:
        dialplan_xml: Complete FreeSWITCH dialplan XML content

    Returns:
        Tuple of (success, output_message)
    """
    content_b64 = base64.b64encode(dialplan_xml.encode()).decode()

    script = f"""\
set -e
BACKUP_DIR=/etc/freeswitch/dialplan/backup
mkdir -p $BACKUP_DIR
cp /etc/freeswitch/dialplan/public.xml $BACKUP_DIR/public.xml.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
echo '{content_b64}' | base64 -d > /etc/freeswitch/dialplan/public.xml
chown www-data:www-data /etc/freeswitch/dialplan/public.xml
fs_cli -x 'reloadxml'
echo 'Dialplan deployed and reloaded successfully'
"""

    try:
        client, RunCommandInput = _get_compute_client()
        log.info(f"Deploying dialplan to PBX VM {PBX_VM_NAME} ({len(dialplan_xml)} bytes)")

        result = client.virtual_machines.begin_run_command(
            resource_group_name=AZURE_RESOURCE_GROUP,
            vm_name=PBX_VM_NAME,
            parameters=RunCommandInput(
                command_id="RunShellScript",
                script=[script],
            ),
        ).result()

        # Extract output from the result
        output_parts = []
        if result.value:
            for msg in result.value:
                if msg.message:
                    output_parts.append(msg.message)

        output = "\n".join(output_parts) if output_parts else "No output"
        success = "successfully" in output.lower() or not any(
            msg.code and "Error" in msg.code for msg in (result.value or [])
        )

        if success:
            log.info(f"Dialplan deployed successfully: {output}")
        else:
            log.error(f"Dialplan deployment failed: {output}")

        return success, output

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Azure VM run-command failed: {e}")
        return False, f"Azure VM run-command failed: {e}"
