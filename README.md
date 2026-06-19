# Garden Security Group Finder

This script scans an AWS account across all regions and extracts every **Security Group whose name contains the word "garden"**. Results are exported to a CSV file.

---

## Quick Start — Run the Script

There are two ways to run this script. **CloudShell is recommended** as it requires no local setup.

---

### Option A — AWS CloudShell (Recommended, no setup needed)

CloudShell runs directly in your browser inside the AWS Console. Credentials are automatic.

**1.** Log in to the AWS Console, then click the **CloudShell icon** in the top navigation bar (terminal icon, next to the bell icon).

**2.** Upload the script — click **Actions → Upload file** and select `find_garden_security_groups.py`.

**3.** Install boto3 and run the script:
```bash
pip install boto3
python find_garden_security_groups.py
```

**4.** Download the results — click **Actions → Download file** and type:
```
garden_security_groups.csv
```

> **Note:** When using CloudShell, make sure `PROFILE_NAME = None` in the script (this is the default).

---

### Option B — Run Locally (requires SSO setup)

Follow the [SSO one-time setup](#aws-credentials-configuration-sso) below, then:

**1.** Log in via AWS SSO:
```powershell
aws sso login --profile <your-profile-name>
```

**2.** Set `PROFILE_NAME = "<your-profile-name>"` at the top of `find_garden_security_groups.py`.

**3.** Run the script:
```powershell
python find_garden_security_groups.py
```

**4.** Open the results:
```
garden_security_groups.csv
```

---

## Prerequisites

Make sure the following tools are installed on your machine before running the script.

### 1. Python
Verify Python is installed by running:
```powershell
python --version
```
If not installed, download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).

---

### 2. AWS CLI
Verify the AWS CLI is installed:
```powershell
aws --version
```
If not installed, follow the official guide: [https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

---

### 3. boto3 (Python AWS SDK)
Install it with:
```powershell
pip install boto3
```
Verify it is available:
```powershell
python -c "import boto3; print(boto3.__version__)"
```

---

## AWS Credentials Configuration (SSO)

This script supports **AWS Single Sign-On (SSO)** via federated identity. You do **not** need an Access Key or Secret Key. Follow the steps below.

---

### Step 1 — Configure the SSO profile (one-time setup)

Run the following command:

```powershell
aws configure sso
```

Enter the values below when prompted:

| Field | Value |
|---|---|
| SSO session name | `<your-profile-name>` |
| SSO start URL | *(see how to find it below)* |
| SSO region | Your AWS region (e.g. `eu-west-1`) |
| SSO registration scopes | Press Enter to accept default |
| Account ID | Your AWS Account ID |
| Role | Your assigned role name |
| Default region | Your AWS region |
| Default output format | `json` |
| Profile name | `<your-profile-name>` |

> **Note:** The SSO start URL must match the one your company uses. If unsure, ask your IT / Cloud team.

#### How to find your SSO Start URL

You already have access to the AWS portal, so the URL is right in front of you:

1. Open your browser and go to the AWS portal login page (the page where you select your AWS account before entering the Console)
2. **The URL in your browser bar IS the SSO Start URL** — it will look like:
   - `https://d-xxxxxxxxxx.awsapps.com/start`
3. Copy everything up to and including `/start`

Alternatively, find it in the AWS Console:
1. Log in to the AWS Console
2. Search for **IAM Identity Center** in the top search bar
3. On the IAM Identity Center dashboard, look for **"AWS access portal URL"** — that is your SSO Start URL

---

### Step 2 — Log in via SSO (required every session)

Each time you start a new terminal session, authenticate first:

```powershell
aws sso login --profile <your-profile-name>
```

This will open a browser window asking you to confirm the login with your corporate credentials. Once approved, return to the terminal.

---

### Step 3 — Verify the login worked

```powershell
aws sts get-caller-identity --profile <your-profile-name>
```

Expected output:
```json
{
    "UserId": "...",
    "Account": "<your-account-id>",
    "Arn": "arn:aws:sts::<your-account-id>:assumed-role/<your-role>/<your-username>"
}
```

---

## Running the Script

Once logged in via SSO (Step 2 above), run the script using the virtual environment Python interpreter:

```powershell
aws sso login --profile <your-profile-name>
python find_garden_security_groups.py
```

The script will:
1. Connect to your AWS account using the configured credentials
2. Retrieve all active AWS regions
3. Scan each region for Security Groups with **"garden"** in their name
4. Save the results to a CSV file in the same folder

---

## Output

The results are saved to:
```
garden_security_groups.csv
```

The CSV contains the following columns:

| Column | Description |
|---|---|
| `AccountId` | AWS Account ID that owns the Security Group |
| `Region` | AWS region where the Security Group was found |
| `SecurityGroupId` | The SG-ID (e.g. `sg-0abc123def456`) |
| `SecurityGroupName` | Full name of the Security Group |
| `VpcId` | ID of the VPC the Security Group belongs to |
| `Description` | Description of the Security Group |

---

## Scanning Specific Regions Only (Optional)

By default, the script scans **all available AWS regions**. If you want to restrict the scan to specific regions, open `find_garden_security_groups.py` and edit the `REGIONS` list at the top of the file:

```python
# Example: scan only EU regions
REGIONS = ["eu-west-1", "eu-west-2", "eu-central-1"]
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `Unable to locate credentials` | Run `aws sso login --profile <your-profile-name>` first |
| `Token has expired` | Your SSO session expired — run `aws sso login --profile <your-profile-name>` again |
| `AuthFailure` or `InvalidClientTokenId` | Wrong profile name — check `PROFILE_NAME` in the script matches your SSO profile |
| `AccessDenied` in a region | Your role may not have `ec2:DescribeSecurityGroups` permission |
| No results in CSV | No Security Groups with "garden" in the name were found in any region |
