"""
Script: find_security_groups.py
Purpose: Find AWS Security Groups matching a name query and export results to CSV.

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


def find_matching_sgs_in_region(session, region, mode, terms, case_sensitive=False):
    """Return Security Groups matching the query in a given region."""
    ec2 = session.client("ec2", region_name=region)
    results = []

    try:
        # AWS-side name filters are case-sensitive.
        # When case-insensitive (default): skip the name filter, fetch all SGs,
        # and rely entirely on client-side lowercase comparison.
        # When case-sensitive: use the AWS filter to pre-filter by name.
        if case_sensitive:
            if mode == "or":
                aws_filters = [{"Name": "group-name", "Values": [f"*{t}*" for t in terms]}]
            else:
                aws_filters = [{"Name": "group-name", "Values": [f"*{terms[0]}*"]}]
        else:
            aws_filters = []  # fetch all, filter client-side

        paginator = ec2.get_paginator("describe_security_groups")
        pages = paginator.paginate(
            Filters=aws_filters
        )
        for page in pages:
            for sg in page["SecurityGroups"]:
                # Client-side match (handles both case modes correctly)
                if matches(sg["GroupName"], mode, terms, case_sensitive):
                    results.append({
                        "AccountId": sg.get("OwnerId", "N/A"),
                        "Region": region,
                        "SecurityGroupId": sg["GroupId"],
                        "SecurityGroupName": sg["GroupName"],
                        "VpcId": sg.get("VpcId", "N/A"),
                        "Description": sg.get("Description", ""),
                    })
    except Exception as e:
        print(f"  [!] Error in region {region}: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Find AWS Security Groups by name and export results to CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python find_security_groups.py "Garden"
      -> finds all SGs whose name contains 'garden' (case-insensitive, default)

  python find_security_groups.py "Garden&Prod"
      -> finds all SGs whose name contains BOTH 'garden' AND 'prod'

  python find_security_groups.py "Garden|Dev"
      -> finds all SGs whose name contains 'garden' OR 'dev'

  python find_security_groups.py "Initial Garden"
      -> finds all SGs whose name contains the exact substring 'initial garden'

  python find_security_groups.py "Garden" --case-sensitive
      -> finds only SGs whose name contains 'Garden' with exact casing
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
    print("  Security Group Finder")
    print(f"  Query          : {args.query}")
    print(f"  Mode           : {mode.upper()} — terms: {terms}")
    print(f"  Case-sensitive : {case_sensitive}")
    print(f"  Started        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Create a boto3 session.
    # - When running in AWS CloudShell: set PROFILE_NAME = None (credentials are automatic)
    # - When running locally after SSO login: set PROFILE_NAME to your configured profile name
    session = boto3.Session(profile_name=PROFILE_NAME) if PROFILE_NAME else boto3.Session()

    # Determine which regions to scan
    regions_to_scan = REGIONS if REGIONS else get_all_regions(session)
    print(f"\nScanning {len(regions_to_scan)} region(s)...\n")

    all_results = []

    for region in regions_to_scan:
        print(f"  Checking region: {region} ...", end=" ")
        found = find_matching_sgs_in_region(session, region, mode, terms, case_sensitive)
        print(f"{len(found)} SG(s) found")
        all_results.extend(found)

    # Write results to CSV
    print(f"\nTotal Security Groups found: {len(all_results)}")

    if all_results:
        fieldnames = ["AccountId", "Region", "SecurityGroupId", "SecurityGroupName", "VpcId", "Description"]
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"Results saved to: {OUTPUT_FILE}")
    else:
        print("No matching Security Groups found.")

    print("\nDone.")


if __name__ == "__main__":
    main()
