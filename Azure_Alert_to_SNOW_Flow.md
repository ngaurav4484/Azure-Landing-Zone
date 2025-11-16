# End-to-End Azure Monitor to ServiceNow Incident Integration

**Document Version:** 1.0  
**Last Updated:** November 16, 2025  
**Author:** Cloud DevOps Engineering  
**Audience:** Cloud Engineers, DevOps Teams, IT Operations

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Components](#architecture-components)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Alert Creation and Processing Flow](#alert-creation-and-processing-flow)
5. [Function App Health Monitoring](#function-app-health-monitoring)
6. [Deployment Prerequisites](#deployment-prerequisites)
7. [Testing and Validation](#testing-and-validation)

---

## Overview

This document describes an automated system that integrates Azure Monitor alerts from multiple subscriptions (Dev, QA, Prod) with ServiceNow incident creation. The system uses a centralized Azure Function App deployed in a dedicated subscription within a Virtual Network, with secure outbound connectivity via NAT Gateway.

**Key Benefits:**
- Automated incident creation in ServiceNow from Azure Monitor alerts
- Secure, isolated Function App with controlled egress
- Complete audit trail via alert-to-incident mapping in Azure Table Storage
- Function App health monitoring with Ops notifications

---

## Architecture Components

| Component | Description | Purpose |
|-----------|-------------|---------|
| **Azure Monitor Alert Rules** | Metric-based or log-based alert definitions | Detect conditions (e.g., CPU > 90%) in resources |
| **Azure Monitor Action Groups** | Notification dispatchers | Send webhook to Function App on alert firing |
| **Azure Function App** | Python-based serverless compute | Process alerts and call ServiceNow API |
| **Azure Virtual Network (VNet)** | Private network isolation | Secure Function App from public internet |
| **NAT Gateway + Static Public IP** | Network Address Translation | Provide fixed egress IP for firewall whitelisting |
| **Azure Storage Account & Table** | Data persistence | Store alert-to-incident mapping records |
| **ServiceNow Incident API** | External incident management system | Create and track incidents |

---

## Infrastructure Setup

### 1. Resource Group Creation

**Terraform Block:** `azurerm_resource_group.central_rg`

```hcl
resource "azurerm_resource_group" "central_rg" {
  name     = "rg-central-monitoring"
  location = var.location
}
```

**What it does:**
- Creates a logical container for all central monitoring resources
- Serves as organizational boundary for billing and access control

---

### 2. Storage Account and Incident Mapping Table

**Terraform Blocks:** 
- `azurerm_storage_account.central_sa`
- `azurerm_storage_table.incident_mapping`

```hcl
resource "azurerm_storage_account" "central_sa" {
  name                     = "centralfuncstore123"
  resource_group_name      = azurerm_resource_group.central_rg.name
  location                 = azurerm_resource_group.central_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_table" "incident_mapping" {
  name                 = "IncidentMapping"
  storage_account_name = azurerm_storage_account.central_sa.name
}
```

**What it does:**
- Stores the Azure Function App function runtime files
- Provides table storage for alert-to-incident mappings
- Records include:
  - Azure alert ID and details
  - ServiceNow incident number and sys_id
  - Timestamp and metadata for audit trail

**Table Structure Example:**
| PartitionKey | RowKey | AzureAlertName | ServiceNowIncidentNumber | ServiceNowSysId | CreatedTimestamp |
|---|---|---|---|---|---|
| HighCPUAlert | 2025-11-16T20:45:00Z | HighCPUAlert | INC0012345 | a1b2c3d4e5f6... | 2025-11-16T20:45:10Z |

---

### 3. Virtual Network and Subnet

**Terraform Blocks:**
- `azurerm_virtual_network.func_vnet`
- `azurerm_subnet.func_subnet`

```hcl
resource "azurerm_virtual_network" "func_vnet" {
  name                = "vnet-central-func"
  location            = azurerm_resource_group.central_rg.location
  resource_group_name = azurerm_resource_group.central_rg.name
  address_space       = ["10.10.0.0/16"]
}

resource "azurerm_subnet" "func_subnet" {
  name                 = "snet-central-func"
  resource_group_name  = azurerm_resource_group.central_rg.name
  virtual_network_name = azurerm_virtual_network.func_vnet.name
  address_prefixes     = ["10.10.1.0/24"]
  
  delegation {
    name = "delegation-microsoft-web"
    service_delegation {
      name = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}
```

**What it does:**
- Creates isolated private network (10.10.0.0/16)
- Delegates subnet to Azure App Service for Function App placement
- Ensures Function App has no public IP address (private only)
- Enables secure outbound routing through NAT Gateway

---

### 4. NAT Gateway and Static Public IP

**Terraform Blocks:**
- `azurerm_public_ip.nat_pip`
- `azurerm_nat_gateway.func_nat`
- `azurerm_subnet_nat_gateway_association.nat_assoc`

```hcl
resource "azurerm_public_ip" "nat_pip" {
  name                = "func-nat-pip"
  resource_group_name = azurerm_resource_group.central_rg.name
  location            = azurerm_resource_group.central_rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "func_nat" {
  name                = "func-nat-gateway"
  location            = azurerm_resource_group.central_rg.location
  resource_group_name = azurerm_resource_group.central_rg.name
  sku_name            = "Standard"
}

resource "azurerm_subnet_nat_gateway_association" "nat_assoc" {
  subnet_id      = azurerm_subnet.func_subnet.id
  nat_gateway_id = azurerm_nat_gateway.func_nat.id
}
```

**What it does:**
- Allocates a **static public IP** (critical for ServiceNow firewall whitelisting)
- Creates NAT Gateway for translating private IPs to public IP
- Associates NAT Gateway with Function subnet
- Ensures all outbound traffic from Function App uses the **same static IP**

**Why it matters:**
- ServiceNow firewall can whitelist a single, predictable IP
- Without NAT, Function outbound IPs would be random/unpredictable
- This is the **IP you share with ServiceNow admins for firewall access**

---

### 5. App Service Plan

**Terraform Block:** `azurerm_app_service_plan.central_plan`

```hcl
resource "azurerm_app_service_plan" "central_plan" {
  name                = "asp-central-function"
  location            = azurerm_resource_group.central_rg.location
  resource_group_name = azurerm_resource_group.central_rg.name
  kind                = "FunctionApp"
  sku {
    tier = "Premium"
    size = "EP1"
  }
  reserved = false
}
```

**What it does:**
- Provisions compute infrastructure to host Function App
- **Premium tier required** for VNet integration (Standard doesn't support it)
- **EP1 size:** 1 vCPU, 3.5 GB RAM (entry-level premium)
- **Always-On enabled** prevents cold starts

---

### 6. Windows Function App

**Terraform Block:** `azurerm_windows_function_app.central_function`

```hcl
resource "azurerm_windows_function_app" "central_function" {
  name                       = "central-funcapp"
  location                   = azurerm_resource_group.central_rg.location
  resource_group_name        = azurerm_resource_group.central_rg.name
  service_plan_id            = azurerm_app_service_plan.central_plan.id
  storage_account_name       = azurerm_storage_account.central_sa.name
  storage_account_access_key = azurerm_storage_account.central_sa.primary_access_key
  functions_extension_version = "~4"
  
  virtual_network_subnet_id = azurerm_subnet.func_subnet.id
  
  site_config {
    always_on               = true
    vnet_route_all_enabled  = true
  }
  
  identity {
    type = "SystemAssigned"
  }
  
  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"        = "python"
    "SERVICENOW_INSTANCE"             = var.servicenow_instance
    "SERVICENOW_USER"                 = var.servicenow_user
    "SERVICENOW_PASSWORD"             = var.servicenow_password
    "AZURE_STORAGE_CONNECTION_STRING" = azurerm_storage_account.central_sa.primary_connection_string
    "WEBSITE_VNET_ROUTE_ALL"          = "1"
  }
}
```

**What it does:**
- **Python Runtime (~4):** Enables Python-based function code execution
- **VNet Integration:** Places Function inside the private subnet (no public IP)
- **Always-On:** Keeps function warm to avoid cold start delays
- **vnet_route_all_enabled:** Routes ALL outbound traffic through VNet and NAT
- **SystemAssigned Managed Identity:** Function authenticates to Azure resources without storing keys
- **App Settings:** Injects ServiceNow credentials and storage connection string for Python code to access

**Critical Configuration:**
- Function is **only reachable internally or via webhook URL with function key**
- ServiceNow credentials stored as **encrypted app settings** (not in code)
- Storage connection string allows Function to write to Table Storage

---

## Alert Creation and Processing Flow

### Step 1: Define Alert Rules

**Terraform Block:** `azurerm_monitor_metric_alert.cpu_alert_dev`

```hcl
resource "azurerm_monitor_metric_alert" "cpu_alert_dev" {
  name                = "HighCPUAlert"
  resource_group_name = "rg-dev"
  scopes = [
    "/subscriptions/${var.subscriptions[0]}/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/vm-dev01"
  ]
  description = "Triggers when VM CPU > 90%"
  severity    = 2
  frequency   = "PT5M"
  window_size = "PT5M"
  
  criteria {
    metric_namespace = "Microsoft.Compute/virtualMachines"
    metric_name      = "Percentage CPU"
    operator         = "GreaterThan"
    threshold        = 90
    aggregation      = "Average"
  }
  
  action {
    action_group_id = azurerm_monitor_action_group.svcnow[var.subscriptions[0]].id
  }
}
```

**What it does:**
- Monitors CPU percentage on `vm-dev01` in Dev subscription
- Evaluates every 5 minutes (frequency = PT5M)
- If average CPU > 90% for 5 minutes → Alert fires
- Links to Action Group to trigger webhook on alert

---

### Step 2: Configure Action Groups

**Terraform Block:** `azurerm_monitor_action_group.svcnow`

```hcl
resource "azurerm_monitor_action_group" "svcnow" {
  for_each = toset(var.subscriptions)
  
  name                = "SendToServiceNow"
  short_name          = "svcnow"
  resource_group_name = "rg-monitoring"
  
  webhook_receiver {
    name                    = "SendToCentralFunctionApp"
    service_uri             = "https://${azurerm_windows_function_app.central_function.default_hostname}/api/SendAlertToServiceNow?code=<function_key>"
    use_common_alert_schema = true
  }
}
```

**What it does:**
- Creates **one Action Group per subscription** (Dev, QA, Prod) using `for_each`
- Configures webhook receiver pointing to Function App
- **Webhook URL includes:**
  - Function App hostname
  - API endpoint: `/api/SendAlertToServiceNow`
  - Function key for authentication: `?code=<function_key>`
- `use_common_alert_schema` ensures consistent JSON payload format

**Webhook Payload Structure:**
When alert fires, Action Group sends POST with:
```json
{
  "schemaId": "Microsoft.Insights/alerting",
  "data": {
    "alertContext": {
      "id": "/subscriptions/xxx/resourceGroups/rg-dev/providers/Microsoft.Insights/metricAlerts/HighCPUAlert",
      "name": "HighCPUAlert",
      "description": "Triggers when VM CPU > 90%",
      "resourceType": "Microsoft.Compute/virtualMachines",
      "resourceName": "vm-dev01",
      "condition": {
        "windowStart": "2025-11-16T20:40:00Z",
        "windowEnd": "2025-11-16T20:45:00Z",
        "metricName": "Percentage CPU",
        "metricValue": 92.5
      },
      "severity": 2
    }
  }
}
```

---

### Step 3: Alert Fires and Webhook is Invoked

**Process:**
1. Azure Monitor detects CPU > 90% condition
2. Alert evaluates to TRUE
3. Alert triggers the Action Group
4. Action Group sends POST request to Function webhook URL
5. Azure Function receives request with alert payload

---

### Step 4: Function App Processes Alert

**Function Code Location:** `SendAlertToServiceNow/__init__.py` (Python function)

**What happens inside Function:**

```python
# Pseudocode - shows the logic flow
def main(req: func.HttpRequest):
    # 1. Parse alert from webhook payload
    alert_data = req.get_json()
    alert_name = alert_data['data']['alertContext']['name']
    alert_metric = alert_data['data']['alertContext']['condition']['metricValue']
    
    # 2. Retrieve ServiceNow credentials from app_settings
    sn_instance = os.environ['SERVICENOW_INSTANCE']
    sn_user = os.environ['SERVICENOW_USER']
    sn_password = os.environ['SERVICENOW_PASSWORD']
    
    # 3. Create incident payload
    incident_payload = {
        "short_description": f"{alert_name}: CPU at {alert_metric}%",
        "description": json.dumps(alert_data, indent=2),
        "severity": "2",
        "urgency": "2",
        "impact": "2"
    }
    
    # 4. Call ServiceNow Incident API
    response = requests.post(
        f"https://{sn_instance}/api/now/table/incident",
        auth=(sn_user, sn_password),
        json=incident_payload
    )
    
    # 5. Extract incident details from response
    if response.status_code == 201:
        sn_response = response.json()
        incident_number = sn_response['result']['number']
        sys_id = sn_response['result']['sys_id']
        
        # 6. Store mapping in Table Storage
        table_client = TableClient.from_connection_string(
            os.environ['AZURE_STORAGE_CONNECTION_STRING'],
            "IncidentMapping"
        )
        
        mapping = {
            'PartitionKey': alert_name,
            'RowKey': datetime.utcnow().isoformat(),
            'AzureAlertId': alert_data['data']['alertContext']['id'],
            'ServiceNowIncidentNumber': incident_number,
            'ServiceNowSysId': sys_id,
            'AlertMetric': alert_metric
        }
        
        table_client.upsert_entity(mapping)
        
        # 7. Return success response
        return func.HttpResponse(
            json.dumps({
                "status": "success",
                "incident_number": incident_number,
                "sys_id": sys_id
            }),
            status_code=200,
            mimetype="application/json"
        )
```

**Key Steps:**
1. **Parse webhook payload** from Azure Monitor
2. **Retrieve credentials** from Function app_settings (injected by Terraform)
3. **Prepare ServiceNow payload** with alert details
4. **Call ServiceNow REST API** via NAT Gateway static IP
5. **Extract incident identifiers** from ServiceNow response
6. **Store mapping** in Azure Table Storage for audit
7. **Return HTTP 200** to confirm successful processing

---

### Step 5: Secure Outbound to ServiceNow (NAT Gateway Path)

**Process:**

```
Function App (inside VNet)
    ↓
All outbound traffic routed to NAT Gateway
    ↓
NAT Gateway translates source IP to Static Public IP
    ↓
ServiceNow firewall receives request from Static IP
    ↓
ServiceNow admin has whitelisted this IP
    ↓
Request reaches ServiceNow API endpoint ✓
```

**Why this works:**
- Function has **no public IP** (private NIC in subnet)
- All internet traffic must go through NAT Gateway
- NAT Gateway has **one static public IP**
- ServiceNow whitelist matches this static IP
- Result: **Secure, predictable egress**

---

### Step 6: ServiceNow Creates Incident

**ServiceNow API Call:**
```
POST https://{servicenow_instance}/api/now/table/incident
Authorization: Basic {base64(user:password)}
Content-Type: application/json

{
  "short_description": "HighCPUAlert: CPU at 92.5%",
  "description": "Full alert JSON...",
  "severity": "2",
  "urgency": "2",
  "impact": "2",
  "assignment_group": "Infrastructure"
}
```

**ServiceNow Response:**
```json
{
  "result": {
    "sys_id": "a1b2c3d4e5f6g7h8i9j0",
    "number": "INC0012345",
    "short_description": "HighCPUAlert: CPU at 92.5%",
    "state": "1",
    "created_on": "2025-11-16T20:45:15Z"
  }
}
```

**What ServiceNow does:**
- Receives authenticated API request
- Creates incident record in incident table
- Generates **incident_number** (human-readable ID)
- Generates **sys_id** (internal database ID)
- Returns both identifiers to Function App

---

### Step 7: Function Stores Mapping in Table Storage

**Terraform Block:** `azurerm_storage_table.incident_mapping` (already created in Step 2)

**Stored Record:**
```
PartitionKey: HighCPUAlert
RowKey: 2025-11-16T20:45:15.123456Z
AzureAlertId: /subscriptions/xxx/resourceGroups/rg-dev/providers/Microsoft.Insights/metricAlerts/HighCPUAlert
AzureResourceName: vm-dev01
AzureMetricName: Percentage CPU
AzureMetricValue: 92.5
ServiceNowIncidentNumber: INC0012345
ServiceNowSysId: a1b2c3d4e5f6g7h8i9j0
ServiceNowIncidentUrl: https://{instance}.service-now.com/nav_to.do?uri=incident.do?sys_id=a1b2c3d4e5f6g7h8i9j0
AlertFiredTimestamp: 2025-11-16T20:45:00Z
FunctionProcessedTimestamp: 2025-11-16T20:45:15Z
FunctionExecutionId: exec-12345-67890
Status: Success
```

**Purpose:**
- **Audit trail:** Links Azure alerts to ServiceNow incidents
- **Correlation:** Enables searching from either system
- **Tracking:** Records timestamps for SLA monitoring
- **Troubleshooting:** Stores function execution ID for diagnostics

---

### Step 8: Function Returns Response

**Response to Action Group:**
```
HTTP 200 OK

{
  "status": "success",
  "incident_number": "INC0012345",
  "sys_id": "a1b2c3d4e5f6g7h8i9j0",
  "mapping_stored": true,
  "function_execution_time_ms": 2340
}
```

**Signals to Action Group:**
- Alert has been successfully processed
- Incident was created in ServiceNow
- Mapping has been stored
- No further retries needed

---

## Function App Health Monitoring

To monitor the health and availability of the Function App itself, additional alert rules are configured.

### HTTP 5xx Errors Alert

**Terraform Block:** `azurerm_monitor_metric_alert.function_http_5xx_alert`

```hcl
resource "azurerm_monitor_metric_alert" "function_http_5xx_alert" {
  name                = "FunctionApp-5xxErrorAlert"
  resource_group_name = azurerm_resource_group.central_rg.name
  scopes              = [azurerm_windows_function_app.central_function.id]
  description         = "Alert when Function App returns HTTP 5xx responses"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT5M"
  
  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "Http5xx"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }
  
  action {
    action_group_id = azurerm_monitor_action_group.function_health_alerts.id
  }
}
```

**What it does:**
- Monitors Function App HTTP 5xx error count
- If any 5xx errors occur → Alert fires
- Sends notification to Ops team

---

### Function Failures Alert

**Terraform Block:** `azurerm_monitor_metric_alert.function_failures_alert`

```hcl
resource "azurerm_monitor_metric_alert" "function_failures_alert" {
  name                = "FunctionApp-FailureAlert"
  resource_group_name = azurerm_resource_group.central_rg.name
  scopes              = [azurerm_windows_function_app.central_function.id]
  description         = "Alert when Function App executions fail"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT5M"
  
  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "FunctionExecutionUnits"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }
  
  action {
    action_group_id = azurerm_monitor_action_group.function_health_alerts.id
  }
}
```

**What it does:**
- Monitors Function execution unit usage
- Detects failures or excessive resource consumption
- Triggers Ops notifications if anomalies detected

---

### Function Availability Alert

**Terraform Block:** `azurerm_monitor_activity_log_alert.function_availability_alert`

```hcl
resource "azurerm_monitor_activity_log_alert" "function_availability_alert" {
  name                = "FunctionApp-DownAlert"
  location            = azurerm_windows_function_app.central_function.location
  resource_group_name = azurerm_resource_group.central_rg.name
  scopes              = [azurerm_windows_function_app.central_function.id]
  description         = "Alert when Function App becomes unavailable or stopped"
  
  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Web/sites/stop/action"
    level          = "Informational"
  }
  
  action {
    action_group_id = azurerm_monitor_action_group.function_health_alerts.id
  }
  
  enabled = true
}
```

**What it does:**
- Monitors Function App stop/start actions
- Alerts if Function is stopped unexpectedly
- Notifies Ops team for immediate investigation

---

### Health Alert Action Group

**Terraform Block:** `azurerm_monitor_action_group.function_health_alerts`

```hcl
resource "azurerm_monitor_action_group" "function_health_alerts" {
  name                = "FunctionAppHealthAlerts"
  resource_group_name = azurerm_resource_group.central_rg.name
  short_name          = "funchealth"
  
  email_receiver {
    name          = "OpsTeamEmail"
    email_address = var.ops_email
  }
  
  webhook_receiver {
    name                    = "TeamsAlertChannel"
    service_uri             = var.teams_webhook
    use_common_alert_schema = true
  }
}
```

**What it does:**
- Sends email to Ops team email address
- Sends notification to Microsoft Teams channel
- Notifies multiple channels simultaneously
- Enables rapid response to Function issues

---

## Deployment Prerequisites

### Before Deploying Terraform

1. **Azure Subscriptions:**
   - One central monitoring subscription (where Function App runs)
   - At least one source subscription (Dev/QA/Prod) with resources to monitor

2. **ServiceNow Access:**
   - ServiceNow instance URL (e.g., `dev123456.service-now.com`)
   - API user credentials with permission to create incidents
   - Firewall access available for whitelisting

3. **Terraform Variables (`terraform.tfvars`):**
   ```hcl
   central_subscription_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   subscriptions           = ["yyyy-yyyy-yyyy-yyyy", "zzzz-zzzz-zzzz-zzzz"]
   location                = "westeurope"
   servicenow_instance     = "dev123456.service-now.com"
   servicenow_user         = "api_user"
   servicenow_password     = "secure_password"
   ops_email               = "ops-team@company.com"
   teams_webhook           = "https://outlook.office.com/webhook/..."
   ```

4. **Azure CLI Authentication:**
   ```bash
   az login
   az account set --subscription "central-subscription-id"
   ```

### Terraform Deployment

```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan -out=tfplan

# Apply configuration
terraform apply tfplan
```

### Post-Deployment Steps

1. **Get Function Key:**
   ```bash
   az functionapp keys list \
     --name central-funcapp \
     --resource-group rg-central-monitoring \
     --query "functionKeys.default" -o tsv
   ```

2. **Update Action Group with Function Key:**
   - Replace `<function_key>` in `azurerm_monitor_action_group.svcnow` webhook URL
   - Reapply Terraform

3. **Get NAT Gateway Public IP:**
   ```bash
   terraform output function_nat_public_ip
   ```

4. **Whitelist IP at ServiceNow:**
   - Share the NAT Gateway public IP with ServiceNow admin
   - Add IP to ServiceNow firewall whitelist
   - Verify outbound connection from Function to ServiceNow

5. **Deploy Function Code:**
   - Create Python function code in `SendAlertToServiceNow/__init__.py`
   - Deploy using Azure Functions Core Tools or VS Code
   ```bash
   func azure functionapp publish central-funcapp
   ```

---

## Testing and Validation

### Test 1: Verify Function Connectivity

```bash
# Manually trigger function with test alert
curl -X POST \
  "https://central-funcapp.azurewebsites.net/api/SendAlertToServiceNow?code=<function_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "alertContext": {
        "name": "TestAlert",
        "condition": {"metricValue": 95}
      }
    }
  }'
```

**Expected Response:**
```json
{
  "status": "success",
  "incident_number": "INC0000001",
  "sys_id": "test_sys_id"
}
```

### Test 2: Verify Table Storage Mapping

```bash
# Query Table Storage for recorded mapping
az storage table entity list \
  --account-name centralfuncstore123 \
  --table-name IncidentMapping
```

**Expected Output:** Mapping record with incident details

### Test 3: Verify ServiceNow Incident Creation

1. Log into ServiceNow instance
2. Navigate to **Incidents** table
3. Verify incident appears with correct title and description
4. Confirm `sys_id` and incident number match stored mapping

### Test 4: End-to-End Alert Test

1. Trigger test alert in Dev/QA/Prod subscription
   ```bash
   az monitor metrics alert create \
     --name TestCPUAlert \
     --resource-group rg-dev \
     --scopes "/subscriptions/.../virtualMachines/vm-test" \
     ...
   ```

2. Monitor Function App logs for execution
   ```bash
   az webapp log tail \
     --name central-funcapp \
     --resource-group rg-central-monitoring
   ```

3. Verify incident created in ServiceNow

4. Query Table Storage to confirm mapping recorded

---

## Outputs

The Terraform configuration provides critical outputs for operational reference:

```hcl
output "function_url" {
  value = "https://${azurerm_windows_function_app.central_function.default_hostname}/api/SendAlertToServiceNow"
}

output "function_app_name" {
  value = azurerm_windows_function_app.central_function.name
}

output "function_nat_public_ip" {
  description = "Static public IP presented for outbound traffic from Function App (NAT). Share with ServiceNow for whitelist."
  value       = azurerm_public_ip.nat_pip.ip_address
}
```

**Use these outputs to:**
- Configure Action Group webhook URLs
- Share NAT IP with ServiceNow admins
- Reference in documentation
- Enable monitoring dashboards

---

## Summary

This end-to-end integration provides:

✓ **Automated incident creation** in ServiceNow from Azure Monitor alerts  
✓ **Secure network architecture** with private Function App and NAT egress  
✓ **Complete audit trail** via alert-to-incident mapping in Table Storage  
✓ **Function App health monitoring** with Ops notifications  
✓ **Production-ready infrastructure** provisioned via Terraform  

The system is scalable to multiple subscriptions, secure with controlled outbound access, and fully auditable for compliance requirements.

---

## Appendix: Quick Reference

| Terraform Block | Purpose | Output |
|---|---|---|
| `azurerm_resource_group.central_rg` | Container for resources | Resource group name |
| `azurerm_storage_account.central_sa` | Function state + mappings | Storage account name |
| `azurerm_storage_table.incident_mapping` | Alert-to-incident correlation | Table name |
| `azurerm_virtual_network.func_vnet` | Private network | VNet ID |
| `azurerm_subnet.func_subnet` | Function subnet | Subnet ID |
| `azurerm_public_ip.nat_pip` | Egress IP address | Static public IP |
| `azurerm_nat_gateway.func_nat` | NAT translation | Gateway ID |
| `azurerm_app_service_plan.central_plan` | Compute for Function | Plan ID |
| `azurerm_windows_function_app.central_function` | Alert processor | Function App hostname |
| `azurerm_monitor_metric_alert.cpu_alert_dev` | CPU monitoring | Alert ID |
| `azurerm_monitor_action_group.svcnow` | Webhook dispatcher | Action Group ID |
| `azurerm_monitor_metric_alert.function_http_5xx_alert` | Function error monitoring | Alert ID |
| `azurerm_monitor_activity_log_alert.function_availability_alert` | Function downtime alert | Alert ID |
| `azurerm_monitor_action_group.function_health_alerts` | Ops notifications | Action Group ID |

---

**End of Document**