"""
Script: find_security_groups.py
Purpose: Find AWS groups (of any type) matching a name query and export results to CSV.

Group types searched:
  - EC2 Security Groups  (per region)
  - IAM User Groups      (global)

Usage:
  python find_security_groups.py "Garden"
  python find_security_groups.py "Garden&Prod"          # AND: name must contain BOTH
  python find_security_groups.py "Garden|Dev"           # OR:  name must contain EITHER
  python find_security_groups.py "Initial Garden"       # exact substring
  python find_security_groups.py "Garden" --case-sensitive  # case-sensitive match
"""

import argparse
import boto3
import csv
import os
from datetime import datetime


# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# AWS SSO profile name (set during 'aws configure sso').
# Set to None when running inside AWS CloudShell (credentials are automatic).
# Set to your profile name when running locally after 'aws sso login --profile <your-profile>'.
PROFILE_NAME = None  # Change to your SSO profile name if running locally (e.g. "my-profile")

# If you want to scan specific regions only, list them here.
# Leave empty [] to automatically scan ALL available AWS regions.
REGIONS = []

# Output CSV file path (same folder as this script)
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "sg_search_results.csv")
# ──────────────────────────────────────────────────────────────────────────────


def parse_query(query):
    """
    Parse the search query and return (mode, terms).

    Modes:
      'and'   — all terms must appear in the name (split by &)
      'or'    — any term must appear in the name (split by |)
      'exact' — the whole string must appear as a substring

    Examples:
      'Garden'         -> ('exact', ['Garden'])
      'Garden&Prod'    -> ('and',   ['Garden', 'Prod'])
      'Garden|Dev'     -> ('or',    ['Garden', 'Dev'])
      'Initial Garden' -> ('exact', ['Initial Garden'])
    """
    if "&" in query:
        terms = [t.strip() for t in query.split("&") if t.strip()]
        return "and", terms
    elif "|" in query:
        terms = [t.strip() for t in query.split("|") if t.strip()]
        return "or", terms
    else:
        return "exact", [query.strip()]


def matches(sg_name, mode, terms, case_sensitive=False):
    """Check if the security group name matches the query."""
    # When case-insensitive (default): compare everything in lowercase
    name = sg_name if case_sensitive else sg_name.lower()
    search_terms = terms if case_sensitive else [t.lower() for t in terms]
    if mode == "and":
        return all(t in name for t in search_terms)
    elif mode == "or":
        return any(t in name for t in search_terms)
    else:  # exact substring
        return search_terms[0] in name


def get_all_regions(session):
    """Return list of all enabled EC2 regions."""
    ec2 = session.client("ec2", region_name="eu-west-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


# ─── SHARED HELPERS ───────────────────────────────────────────────────────────

def _handle_error(group_type, location, error):
    """Print a meaningful error message, distinguishing access denied from other errors."""
    code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
    access_denied_codes = {
        "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
        "AuthorizationError", "UnauthorizedAccess",
        "AWSOrganizationsNotInUseException", "OptInRequired",
    }
    if code in access_denied_codes:
        print(f"  [NO ACCESS] {group_type} ({location}): {code}")
    else:
        print(f"  [ERROR] {group_type} ({location}): {error}")


def _result(group_type, account_id, region, group_id, group_name, info="", description=""):
    """Build a unified result dict."""
    return {
        "Type": group_type,
        "AccountId": account_id,
        "Region": region,
        "GroupId": group_id,
        "GroupName": group_name,
        "AdditionalInfo": info,
        "Description": description,
    }


# ─── REGIONAL SEARCHERS (called once per region) ──────────────────────────────

def search_ec2_security_groups(session, account_id, region, mode, terms, case_sensitive):
    """EC2 Security Groups — virtual firewalls controlling network traffic."""
    ec2 = session.client("ec2", region_name=region)
    results = []
    try:
        # AWS name filters are case-sensitive; skip when case-insensitive and filter client-side
        if case_sensitive:
            values = [f"*{t}*" for t in terms] if mode == "or" else [f"*{terms[0]}*"]
            aws_filters = [{"Name": "group-name", "Values": values}]
        else:
            aws_filters = []
        for page in ec2.get_paginator("describe_security_groups").paginate(Filters=aws_filters):
            for sg in page["SecurityGroups"]:
                if matches(sg["GroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "EC2 Security Group", sg.get("OwnerId", account_id), region,
                        sg["GroupId"], sg["GroupName"],
                        f"VpcId: {sg.get('VpcId', 'N/A')}", sg.get("Description", ""),
                    ))
    except Exception as e:
        _handle_error("EC2 Security Groups", region, e)
        return None
    return results


def search_autoscaling_groups(session, account_id, region, mode, terms, case_sensitive):
    """Auto Scaling Groups — groups of EC2 instances that scale automatically."""
    asg = session.client("autoscaling", region_name=region)
    results = []
    try:
        for page in asg.get_paginator("describe_auto_scaling_groups").paginate():
            for g in page["AutoScalingGroups"]:
                if matches(g["AutoScalingGroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "Auto Scaling Group", account_id, region,
                        g["AutoScalingGroupARN"], g["AutoScalingGroupName"],
                        f"Min: {g['MinSize']}, Max: {g['MaxSize']}, Desired: {g['DesiredCapacity']}",
                    ))
    except Exception as e:
        _handle_error("Auto Scaling Groups", region, e)
        return None
    return results


def search_target_groups(session, account_id, region, mode, terms, case_sensitive):
    """ELB Target Groups — destination groups for Application/Network Load Balancers."""
    elb = session.client("elbv2", region_name=region)
    results = []
    try:
        for page in elb.get_paginator("describe_target_groups").paginate():
            for tg in page["TargetGroups"]:
                if matches(tg["TargetGroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "ELB Target Group", account_id, region,
                        tg["TargetGroupArn"], tg["TargetGroupName"],
                        f"Protocol: {tg.get('Protocol','N/A')}, Port: {tg.get('Port','N/A')}, Type: {tg.get('TargetType','N/A')}",
                    ))
    except Exception as e:
        _handle_error("ELB Target Groups", region, e)
        return None
    return results


def search_resource_groups(session, account_id, region, mode, terms, case_sensitive):
    """Resource Groups — logical groupings of AWS resources."""
    rg = session.client("resource-groups", region_name=region)
    results = []
    try:
        for page in rg.get_paginator("list_groups").paginate():
            for g in page.get("GroupIdentifiers", []):
                if matches(g["GroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "Resource Group", account_id, region,
                        g["GroupArn"], g["GroupName"],
                    ))
    except Exception as e:
        _handle_error("Resource Groups", region, e)
        return None
    return results


def search_rds_subnet_groups(session, account_id, region, mode, terms, case_sensitive):
    """RDS Subnet Groups — subnet groups used by RDS database instances."""
    rds = session.client("rds", region_name=region)
    results = []
    try:
        for page in rds.get_paginator("describe_db_subnet_groups").paginate():
            for g in page["DBSubnetGroups"]:
                if matches(g["DBSubnetGroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "RDS Subnet Group", account_id, region,
                        g["DBSubnetGroupArn"], g["DBSubnetGroupName"],
                        f"VpcId: {g.get('VpcId','N/A')}", g.get("DBSubnetGroupDescription", ""),
                    ))
    except Exception as e:
        _handle_error("RDS Subnet Groups", region, e)
        return None
    return results


def search_elasticache_subnet_groups(session, account_id, region, mode, terms, case_sensitive):
    """ElastiCache Subnet Groups — subnet groups used by Redis/Memcached clusters."""
    ec = session.client("elasticache", region_name=region)
    results = []
    try:
        for page in ec.get_paginator("describe_cache_subnet_groups").paginate():
            for g in page["CacheSubnetGroups"]:
                if matches(g["CacheSubnetGroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "ElastiCache Subnet Group", account_id, region,
                        g.get("ARN", "N/A"), g["CacheSubnetGroupName"],
                        f"VpcId: {g.get('VpcId','N/A')}", g.get("CacheSubnetGroupDescription", ""),
                    ))
    except Exception as e:
        _handle_error("ElastiCache Subnet Groups", region, e)
        return None
    return results


def search_placement_groups(session, account_id, region, mode, terms, case_sensitive):
    """EC2 Placement Groups — control physical placement of EC2 instances."""
    ec2 = session.client("ec2", region_name=region)
    results = []
    try:
        for g in ec2.describe_placement_groups().get("PlacementGroups", []):
            if matches(g["GroupName"], mode, terms, case_sensitive):
                results.append(_result(
                    "EC2 Placement Group", account_id, region,
                    g.get("GroupId", "N/A"), g["GroupName"],
                    f"Strategy: {g.get('Strategy','N/A')}, State: {g.get('State','N/A')}",
                ))
    except Exception as e:
        _handle_error("EC2 Placement Groups", region, e)
        return None
    return results


# ─── GLOBAL SEARCHERS (called once) ───────────────────────────────────────────

def search_iam_user_groups(session, account_id, mode, terms, case_sensitive):
    """IAM User Groups — groups of IAM users sharing the same permissions."""
    iam = session.client("iam")
    results = []
    try:
        for page in iam.get_paginator("list_groups").paginate():
            for g in page["Groups"]:
                if matches(g["GroupName"], mode, terms, case_sensitive):
                    results.append(_result(
                        "IAM User Group", account_id, "global",
                        g["GroupId"], g["GroupName"],
                        f"Path: {g.get('Path', '/')}",
                    ))
    except Exception as e:
        _handle_error("IAM User Groups", "global", e)
        return None
    return results


def search_organizations_ous(session, account_id, mode, terms, case_sensitive):
    """Organizations OUs — Organizational Units in AWS Organizations (management account only)."""
    org = session.client("organizations")
    results = []

    def _traverse(parent_id):
        try:
            for page in org.get_paginator("list_organizational_units_for_parent").paginate(ParentId=parent_id):
                for ou in page["OrganizationalUnits"]:
                    if matches(ou["Name"], mode, terms, case_sensitive):
                        results.append(_result(
                            "Organizations OU", account_id, "global",
                            ou["Id"], ou["Name"], f"ParentId: {parent_id}",
                        ))
                    _traverse(ou["Id"])
        except Exception:
            pass  # Stop recursion silently on sub-level errors

    try:
        roots = org.list_roots()["Roots"]
        for root in roots:
            if matches(root["Name"], mode, terms, case_sensitive):
                results.append(_result(
                    "Organizations Root", account_id, "global",
                    root["Id"], root["Name"], "Root",
                ))
            _traverse(root["Id"])
    except Exception as e:
        _handle_error("Organizations OUs", "global", e)
        return None
    return results


# ─── SEARCHER REGISTRIES ──────────────────────────────────────────────────────
# Regional searchers are called once per AWS region.
REGIONAL_SEARCHERS = [
    ("EC2 Security Groups",       search_ec2_security_groups),
    ("Auto Scaling Groups",       search_autoscaling_groups),
    ("ELB Target Groups",         search_target_groups),
    ("Resource Groups",           search_resource_groups),
    ("RDS Subnet Groups",         search_rds_subnet_groups),
    ("ElastiCache Subnet Groups", search_elasticache_subnet_groups),
    ("EC2 Placement Groups",      search_placement_groups),
]
# Global searchers are called once regardless of region count.
GLOBAL_SEARCHERS = [
    ("IAM User Groups",           search_iam_user_groups),
    ("Organizations OUs",         search_organizations_ous),
]


def main():
    parser = argparse.ArgumentParser(
        description="Find AWS groups of any type matching a name query and export to CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
group types searched:
  EC2 Security Groups, Auto Scaling Groups, ELB Target Groups, Resource Groups,
  RDS Subnet Groups, ElastiCache Subnet Groups, EC2 Placement Groups,
  IAM User Groups, Organizations OUs

examples:
  python find_security_groups.py "Garden"
      -> all groups whose name contains 'garden' (case-insensitive, default)

  python find_security_groups.py "Garden&Prod"
      -> all groups whose name contains BOTH 'garden' AND 'prod'

  python find_security_groups.py "Garden|Dev"
      -> all groups whose name contains 'garden' OR 'dev'

  python find_security_groups.py "Initial Garden"
      -> all groups whose name contains the exact substring 'initial garden'

  python find_security_groups.py "Garden" --case-sensitive
      -> only groups whose name contains 'Garden' with exact casing
        """
    )
    parser.add_argument(
        "query",
        help="Search query. Use & for AND, | for OR, or plain text for substring match."
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        default=False,
        help="Enable case-sensitive matching. Default is case-insensitive."
    )
    args = parser.parse_args()

    mode, terms = parse_query(args.query)
    case_sensitive = args.case_sensitive

    print("=" * 60)
    print("  AWS Group Finder")
    print(f"  Query          : {args.query}")
    print(f"  Mode           : {mode.upper()} — terms: {terms}")
    print(f"  Case-sensitive : {case_sensitive}")
    print(f"  Started        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Create boto3 session
    session = boto3.Session(profile_name=PROFILE_NAME) if PROFILE_NAME else boto3.Session()

    # Get account ID once (reused by all searchers)
    account_id = session.client("sts").get_caller_identity()["Account"]

    regions_to_scan = REGIONS if REGIONS else get_all_regions(session)
    all_results = []

    # ── GLOBAL SEARCHERS ──────────────────────────────────────────────────────
    print(f"\n[ Global services ]\n")
    for name, fn in GLOBAL_SEARCHERS:
        print(f"  {name} ...", end=" ", flush=True)
        found = fn(session, account_id, mode, terms, case_sensitive)
        if found is not None:
            print(f"{len(found)} found")
            all_results.extend(found)

    # ── REGIONAL SEARCHERS ────────────────────────────────────────────────────
    print(f"\n[ Regional services — {len(regions_to_scan)} region(s) ]\n")
    for region in regions_to_scan:
        print(f"  {region}:")
        for name, fn in REGIONAL_SEARCHERS:
            print(f"    {name} ...", end=" ", flush=True)
            found = fn(session, account_id, region, mode, terms, case_sensitive)
            if found is not None:
                print(f"{len(found)} found")
                all_results.extend(found)

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Total groups found: {len(all_results)}")
    print(f"{'=' * 60}")

    if all_results:
        fieldnames = ["Type", "AccountId", "Region", "GroupId", "GroupName", "AdditionalInfo", "Description"]
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"  Results saved to: {OUTPUT_FILE}")
    else:
        print("  No matching groups found.")

    print("\nDone.")


if __name__ == "__main__":
    main()
