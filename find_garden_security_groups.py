"""
Script: find_garden_security_groups.py
Purpose: Find all AWS Security Groups whose name contains "garden" (case-insensitive)
         and export results to a CSV file.
"""

import boto3
import csv
import os
from datetime import datetime


# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# AWS SSO profile name (set during 'aws configure sso').
# Set to None when running inside AWS CloudShell (credentials are automatic).
# Set to "sgn-sandbox" when running locally after 'aws sso login --profile sgn-sandbox'.
PROFILE_NAME = None  # Change to "sgn-sandbox" if running locally

# If you want to scan specific regions only, list them here.
# Leave empty [] to automatically scan ALL available AWS regions.
REGIONS = []

# Output CSV file path (same folder as this script)
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "garden_security_groups.csv")
# ──────────────────────────────────────────────────────────────────────────────


def get_all_regions(session):
    """Return list of all enabled EC2 regions."""
    ec2 = session.client("ec2", region_name="eu-west-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


def find_garden_sgs_in_region(session, region):
    """Return Security Groups with 'garden' in their name for a given region."""
    ec2 = session.client("ec2", region_name=region)
    results = []

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        pages = paginator.paginate(
            Filters=[{"Name": "group-name", "Values": ["*garden*"]}]
        )
        for page in pages:
            for sg in page["SecurityGroups"]:
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
    print("=" * 60)
    print("  SGN - Garden Security Group Finder")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Create a boto3 session.
    # - When running in AWS CloudShell: set PROFILE_NAME = None (credentials are automatic)
    # - When running locally after SSO login: set PROFILE_NAME = "sgn-sandbox"
    session = boto3.Session(profile_name=PROFILE_NAME) if PROFILE_NAME else boto3.Session()

    # Determine which regions to scan
    regions_to_scan = REGIONS if REGIONS else get_all_regions(session)
    print(f"\nScanning {len(regions_to_scan)} region(s)...\n")

    all_results = []

    for region in regions_to_scan:
        print(f"  Checking region: {region} ...", end=" ")
        found = find_garden_sgs_in_region(session, region)
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
        print("No Security Groups with 'garden' in the name were found.")

    print("\nDone.")


if __name__ == "__main__":
    main()
