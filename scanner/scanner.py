import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"


def finding(
    finding_id,
    severity,
    service,
    resource,
    title,
    description,
    evidence,
    remediation,
):
    return {
        "finding_id": finding_id,
        "severity": severity,
        "service": service,
        "resource": resource,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


def check_security_groups(ec2):
    findings = []

    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        group_id = sg["GroupId"]
        group_name = sg.get("GroupName", "unknown")

        for rule in sg.get("IpPermissions", []):
            protocol = rule.get("IpProtocol")

            if protocol != "tcp":
                continue

            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            for port in range(from_port or 0, (to_port or 0) + 1):
                for cidr in rule.get("IpRanges", []):
                    cidr_ip = cidr.get("CidrIp")

                    if cidr_ip != "0.0.0.0/0":
                        continue

                    if port == 22:
                        findings.append(
                            finding(
                                "SG-001",
                                "HIGH",
                                "EC2",
                                group_id,
                                "SSH exposed to the public internet",
                                (
                                    f"Security group {group_name} allows "
                                    "TCP/22 from 0.0.0.0/0."
                                ),
                                {
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "protocol": protocol,
                                    "port": port,
                                    "cidr": cidr_ip,
                                },
                                (
                                    "Restrict SSH access to a trusted IP range "
                                    "or remove the rule and use a managed access "
                                    "mechanism such as AWS Systems Manager."
                                ),
                            )
                        )

                    if port == 3389:
                        findings.append(
                            finding(
                                "SG-002",
                                "HIGH",
                                "EC2",
                                group_id,
                                "RDP exposed to the public internet",
                                (
                                    f"Security group {group_name} allows "
                                    "TCP/3389 from 0.0.0.0/0."
                                ),
                                {
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "protocol": protocol,
                                    "port": port,
                                    "cidr": cidr_ip,
                                },
                                (
                                    "Restrict RDP access to a trusted network "
                                    "or use a managed remote-access solution."
                                ),
                            )
                        )

    return findings


def check_s3(s3):
    findings = []

    response = s3.list_buckets()

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        try:
            public_access = s3.get_public_access_block(
                Bucket=bucket_name
            )["PublicAccessBlockConfiguration"]

            protections = [
                public_access.get("BlockPublicAcls", False),
                public_access.get("IgnorePublicAcls", False),
                public_access.get("BlockPublicPolicy", False),
                public_access.get("RestrictPublicBuckets", False),
            ]

            if not all(protections):
                findings.append(
                    finding(
                        "S3-001",
                        "HIGH",
                        "S3",
                        bucket_name,
                        "S3 public access protection is incomplete",
                        "One or more S3 Block Public Access controls are disabled.",
                        public_access,
                        "Enable all four S3 Block Public Access controls.",
                    )
                )

        except ClientError as error:
            if error.response["Error"]["Code"] == (
                "NoSuchPublicAccessBlockConfiguration"
            ):
                findings.append(
                    finding(
                        "S3-001",
                        "HIGH",
                        "S3",
                        bucket_name,
                        "S3 public access protection is not configured",
                        (
                            "The bucket does not have an S3 Block Public "
                            "Access configuration."
                        ),
                        {"bucket": bucket_name},
                        "Enable all four S3 Block Public Access controls.",
                    )
                )

        try:
            s3.get_bucket_encryption(Bucket=bucket_name)

        except ClientError as error:
            if error.response["Error"]["Code"] in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchBucket",
            ):
                findings.append(
                    finding(
                        "S3-002",
                        "MEDIUM",
                        "S3",
                        bucket_name,
                        "S3 bucket encryption is not configured",
                        (
                            "No default server-side encryption configuration "
                            "was detected."
                        ),
                        {"bucket": bucket_name},
                        "Enable default server-side encryption for the bucket.",
                    )
                )

    return findings


def check_cloudtrail(cloudtrail):
    findings = []

    response = cloudtrail.describe_trails(includeShadowTrails=False)
    trails = response.get("trailList", [])

    if not trails:
        findings.append(
            finding(
                "CT-001",
                "HIGH",
                "CloudTrail",
                "account",
                "CloudTrail is not configured",
                "No CloudTrail trail was detected in the account.",
                {"trail_count": 0},
                "Create and enable a CloudTrail trail for API activity monitoring.",
            )
        )

    return findings


def check_iam(iam):
    findings = []

    try:
        paginator = iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]

                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy["DefaultVersionId"],
                    )

                    document = version["PolicyVersion"]["Document"]

                    statements = document.get("Statement", [])

                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:
                        effect = statement.get("Effect")
                        actions = statement.get("Action")
                        resources = statement.get("Resource")

                        if (
                            effect == "Allow"
                            and actions == "*"
                            and resources == "*"
                        ):
                            findings.append(
                                finding(
                                    "IAM-001",
                                    "CRITICAL",
                                    "IAM",
                                    policy_arn,
                                    "IAM policy grants full administrative permissions",
                                    (
                                        f"Policy {policy_name} allows "
                                        "all actions on all resources."
                                    ),
                                    {
                                        "policy_name": policy_name,
                                        "policy_arn": policy_arn,
                                        "effect": effect,
                                        "action": actions,
                                        "resource": resources,
                                    },
                                    (
                                        "Replace wildcard permissions with "
                                        "the minimum actions and resources "
                                        "required by the workload."
                                    ),
                                )
                            )

                except ClientError:
                    continue

    except ClientError as error:
        print(f"[!] IAM scan error: {error}")

    return findings


def check_attack_paths(ec2, iam):
    findings = []

    print("[*] Analyzing cloud attack paths...")

    try:
        response = ec2.describe_instances(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                }
            ]
        )

        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]

                public_ip = instance.get("PublicIpAddress")

                if not public_ip:
                    continue

                security_groups = [
                    sg["GroupId"]
                    for sg in instance.get("SecurityGroups", [])
                ]

                instance_profile = instance.get("IamInstanceProfile")

                if not instance_profile:
                    continue

                profile_arn = instance_profile["Arn"]

                profile_name = profile_arn.split("/")[-1]

                try:
                    profile = iam.get_instance_profile(
                        InstanceProfileName=profile_name
                    )

                except ClientError:
                    continue

                roles = profile["InstanceProfile"].get("Roles", [])

                for role in roles:
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]

                    try:
                        attached = iam.list_attached_role_policies(
                            RoleName=role_name
                        )

                    except ClientError:
                        continue

                    for policy in attached.get("AttachedPolicies", []):
                        policy_arn = policy["PolicyArn"]

                        try:
                            version = iam.get_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=iam.get_policy(
                                    PolicyArn=policy_arn
                                )["Policy"]["DefaultVersionId"],
                            )

                            document = version["PolicyVersion"]["Document"]

                        except ClientError:
                            continue

                        statements = document.get("Statement", [])

                        if isinstance(statements, dict):
                            statements = [statements]

                        for statement in statements:
                            if (
                                statement.get("Effect") == "Allow"
                                and statement.get("Action") == "*"
                                and statement.get("Resource") == "*"
                            ):
                                findings.append(
                                    finding(
                                        "AP-001",
                                        "CRITICAL",
                                        "Attack Path",
                                        instance_id,
                                        "Public EC2 instance has an overprivileged IAM role",
                                        (
                                            "A publicly reachable EC2 instance "
                                            "is associated with an IAM role that "
                                            "grants all actions on all resources."
                                        ),
                                        {
                                            "instance_id": instance_id,
                                            "public_ip": public_ip,
                                            "security_groups": security_groups,
                                            "instance_profile": profile_arn,
                                            "role_name": role_name,
                                            "role_arn": role_arn,
                                            "policy_name": policy["PolicyName"],
                                            "policy_arn": policy_arn,
                                            "action": statement.get("Action"),
                                            "resource": statement.get("Resource"),
                                        },
                                        (
                                            "Remove unnecessary public exposure, "
                                            "restrict SSH access, and replace the "
                                            "wildcard IAM policy with least-privilege "
                                            "permissions."
                                        ),
                                    )
                                )

    except ClientError as error:
        print(f"[!] Attack-path analysis error: {error}")

    return findings


def enrich_findings(findings):
    risk_data = {
        "SG-001": {
            "risk_score": 8.0,
            "attack_technique": "T1021.004",
            "attack_technique_name": "SSH",
        },
        "SG-002": {
            "risk_score": 8.0,
            "attack_technique": "T1021.001",
            "attack_technique_name": "RDP",
        },
        "CT-001": {
            "risk_score": 7.0,
            "attack_technique": None,
            "attack_technique_name": None,
        },
        "IAM-001": {
            "risk_score": 9.5,
            "attack_technique": None,
            "attack_technique_name": None,
        },
        "AP-001": {
            "risk_score": 10.0,
            "attack_technique": "T1078",
            "attack_technique_name": "Valid Accounts",
        },
    }

    for item in findings:
        data = risk_data.get(
            item["finding_id"],
            {
                "risk_score": 5.0,
                "attack_technique": None,
                "attack_technique_name": None,
            },
        )

        item["risk_score"] = data["risk_score"]
        item["attack_technique"] = data["attack_technique"]
        item["attack_technique_name"] = data["attack_technique_name"]

    return findings


def main():
    session = boto3.Session(region_name=REGION)

    ec2 = session.client("ec2")
    s3 = session.client("s3")
    cloudtrail = session.client("cloudtrail")
    iam = session.client("iam")

    findings = []

    print("[*] Running cloud security posture scan...")
    print(f"[*] Region: {REGION}")

    findings.extend(check_security_groups(ec2))
    findings.extend(check_s3(s3))
    findings.extend(check_cloudtrail(cloudtrail))
    findings.extend(check_iam(iam))
    findings.extend(check_attack_paths(ec2, iam))

    findings = enrich_findings(findings)

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "region": REGION,
        "finding_count": len(findings),
        "findings": findings,
    }

    with open("../findings/scan-results.json", "w") as file:
        json.dump(report, file, indent=2)

    print()
    print(f"[+] Scan complete: {len(findings)} finding(s)")

    for item in findings:
        print(
            f"[{item['severity']}] "
            f"{item['finding_id']} - "
            f"{item['title']} "
            f"({item['resource']})"
        )

    print()
    print("[+] Report saved to ../findings/scan-results.json")


if __name__ == "__main__":
    main()
