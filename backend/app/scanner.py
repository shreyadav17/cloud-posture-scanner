
from datetime import datetime, timezone
import csv
import io
import time

import boto3
from botocore.exceptions import ClientError

from .config import AWS_REGION, DYNAMODB_TABLE


def _session():
    return boto3.Session(region_name=AWS_REGION)


def _error(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Message", str(e))
    return str(e)


def discover_instances(session):
    ec2 = session.client("ec2")
    out = []

    regions = [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=False).get("Regions", [])
    ]

    for region in regions:
        client = session.client("ec2", region_name=region)
        paginator = client.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for item in reservation.get("Instances", []):
                    out.append({
                        "instance_id": item["InstanceId"],
                        "instance_type": item.get("InstanceType"),
                        "region": region,
                        "public_ip": item.get("PublicIpAddress"),
                        "security_groups": [
                            g.get("GroupId")
                            for g in item.get("SecurityGroups", [])
                        ]
                    })

    return out, regions



def discover_buckets(session):
    s3 = session.client("s3")
    out = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]

        item = {
            "bucket_name": name,
            "region": "unknown",
            "encrypted": None,
            "public": None,
            "public_evidence": ""
        }

        try:
            loc = (
                s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                or "us-east-1"
            )

            if loc == "EU":
                loc = "eu-west-1"

            item["region"] = loc
            client = session.client("s3", region_name=loc)

            try:
                client.get_bucket_encryption(Bucket=name)
                item["encrypted"] = True
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in (
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "NotFound"
                ):
                    item["encrypted"] = False
                else:
                    item["public_evidence"] += (
                        f"Encryption inspection error: {_error(e)}; "
                    )

            evidence = []
            public = False
            unknown = False

            try:
                p = client.get_public_access_block(
                    Bucket=name
                )["PublicAccessBlockConfiguration"]

                if not all(
                    p.get(k, False)
                    for k in (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets"
                    )
                ):
                    evidence.append(
                        "Bucket public access block settings are incomplete"
                    )

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")

                if code == "NoSuchPublicAccessBlockConfiguration":
                    evidence.append(
                        "No bucket-level public access block configuration"
                    )
                else:
                    unknown = True
                    evidence.append(
                        f"Public access block inspection error: {_error(e)}"
                    )

            try:
                policy_status = client.get_bucket_policy_status(
                    Bucket=name
                ).get("PolicyStatus", {}).get("IsPublic", False)

                if policy_status:
                    public = True
                    evidence.append("Bucket policy status is public")

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")

                if code not in (
                    "NoSuchBucketPolicy",
                    "NoSuchBucketPolicyException"
                ):
                    unknown = True
                    evidence.append(
                        f"Bucket policy inspection error: {_error(e)}"
                    )

            try:
                acl = client.get_bucket_acl(Bucket=name)

                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")

                    if uri.endswith(("AllUsers", "AuthenticatedUsers")):
                        public = True
                        evidence.append(
                            "Bucket ACL grants access to a public group"
                        )

            except ClientError as e:
                unknown = True
                evidence.append(
                    f"Bucket ACL inspection error: {_error(e)}"
                )

            if public:
                item["public"] = True
            elif unknown:
                item["public"] = None
            else:
                item["public"] = False

            item["public_evidence"] = (
                "; ".join(evidence)
                if evidence
                else "No public policy/ACL detected"
            )

        except Exception as e:
            item["public"] = None
            item["public_evidence"] = (
                f"Bucket inspection error: {_error(e)}"
            )

        out.append(item)

    return out

def check_root_mfa(session):
    iam = session.client("iam")

    try:
        iam.generate_credential_report()

        report = None

        for attempt in range(10):
            try:
                response = iam.get_credential_report()
                report = response["Content"].decode("utf-8")
                break

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")

                if code not in (
                    "ReportInProgress",
                    "ReportNotPresent"
                ):
                    raise

                if attempt == 9:
                    raise

                time.sleep(3)

        if report is None:
            return {
                "check_id": "ROOT_MFA",
                "title": "Root account MFA is enabled",
                "status": "ERROR",
                "evidence": "Credential report was not available"
            }

        rows = list(csv.DictReader(io.StringIO(report)))

        root = next(
            (
                row for row in rows
                if row.get("user") == "<root_account>"
            ),
            None
        )

        if not root:
            return {
                "check_id": "ROOT_MFA",
                "title": "Root account MFA is enabled",
                "status": "UNKNOWN",
                "evidence": "Root account row not found in credential report"
            }

        active = root.get("mfa_active", "false").lower() == "true"

        return {
            "check_id": "ROOT_MFA",
            "title": "Root account MFA is enabled",
            "status": "PASS" if active else "FAIL",
            "evidence": f"Credential report mfa_active={root.get('mfa_active')}"
        }

    except Exception as e:
        return {
            "check_id": "ROOT_MFA",
            "title": "Root account MFA is enabled",
            "status": "ERROR",
            "evidence": _error(e)
        }


def check_cloudtrail(session, regions):
    found = []
    errors = []

    for region in regions:
        try:
            ct = session.client("cloudtrail", region_name=region)

            trails = ct.describe_trails(
                includeShadowTrails=True
            ).get("trailList", [])

            for trail in trails:
                status = ct.get_trail_status(
                    Name=trail["TrailARN"]
                )

                if status.get("IsLogging"):
                    entry = f'{trail.get("Name")} ({region})'

                    if entry not in found:
                        found.append(entry)

        except Exception as e:
            errors.append(f"{region}: {_error(e)}")

    if found:
        return {
            "check_id": "CLOUDTRAIL",
            "title": "CloudTrail is enabled",
            "status": "PASS",
            "evidence": "Logging trail(s): " + ", ".join(found)
        }

    if errors:
        return {
            "check_id": "CLOUDTRAIL",
            "title": "CloudTrail is enabled",
            "status": "ERROR",
            "evidence": (
                "No active trail confirmed; inspection errors: "
                + "; ".join(errors[:3])
            )
        }

    return {
        "check_id": "CLOUDTRAIL",
        "title": "CloudTrail is enabled",
        "status": "FAIL",
        "evidence": "No logging CloudTrail trail found in inspected regions"
    }


def check_ssh_rdp(session, regions):
    exposed = []
    errors = []

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):

                    for perm in sg.get("IpPermissions", []):
                        proto = perm.get("IpProtocol")
                        ports = []

                        if proto == "-1":
                            ports = [22, 3389]

                        elif proto in ("tcp", "6"):
                            lo = perm.get("FromPort", -1)
                            hi = perm.get("ToPort", -1)

                            ports = [
                                p for p in (22, 3389)
                                if lo <= p <= hi
                            ]

                        if not ports:
                            continue

                        ipv4_open = any(
                            rng.get("CidrIp") == "0.0.0.0/0"
                            for rng in perm.get("IpRanges", [])
                        )

                        ipv6_open = any(
                            rng.get("CidrIpv6") == "::/0"
                            for rng in perm.get("Ipv6Ranges", [])
                        )

                        if ipv4_open or ipv6_open:
                            exposed.append(
                                f'{sg.get("GroupId")} ({region}) '
                                f'port(s) {ports}, '
                                f'IPv4={ipv4_open}, IPv6={ipv6_open}'
                            )

        except Exception as e:
            errors.append(f"{region}: {_error(e)}")

    if exposed:
        return {
            "check_id": "SSH_RDP",
            "title": "Security groups do not expose SSH/RDP to the internet",
            "status": "FAIL",
            "evidence": "Public ingress: " + "; ".join(exposed[:20])
        }

    if errors:
        return {
            "check_id": "SSH_RDP",
            "title": "Security groups do not expose SSH/RDP to the internet",
            "status": "ERROR",
            "evidence": (
                "Could not inspect all regions: "
                + "; ".join(errors[:3])
            )
        }

    return {
        "check_id": "SSH_RDP",
        "title": "Security groups do not expose SSH/RDP to the internet",
        "status": "PASS",
        "evidence": (
            "No SSH/RDP ingress from 0.0.0.0/0 or ::/0 found"
        )
    }


def run_scan():
    session = _session()

    instances, regions = discover_instances(session)
    buckets = discover_buckets(session)

    checks = []

    if not buckets:
        public_status = "UNKNOWN"
        enc_status = "UNKNOWN"

        public_evidence = (
            "No S3 buckets found; check could not be evaluated"
        )

        enc_evidence = (
            "No S3 buckets found; check could not be evaluated"
        )

    else:
        if any(b["public"] is True for b in buckets):
            public_status = "FAIL"

        elif any(b["public"] is None for b in buckets):
            public_status = "ERROR"

        else:
            public_status = "PASS"

        if any(b["encrypted"] is False for b in buckets):
            enc_status = "FAIL"

        elif any(b["encrypted"] is None for b in buckets):
            enc_status = "ERROR"

        else:
            enc_status = "PASS"

        public_evidence = "; ".join(
            f'{b["bucket_name"]}: {b["public_evidence"]}'
            for b in buckets
        )

        enc_evidence = "; ".join(
            f'{b["bucket_name"]}: encrypted={b["encrypted"]}'
            for b in buckets
        )

    checks.append({
        "check_id": "S3_PUBLIC",
        "title": "S3 buckets are not publicly accessible",
        "status": public_status,
        "evidence": public_evidence
    })

    checks.append({
        "check_id": "S3_ENCRYPTION",
        "title": "All S3 buckets are encrypted",
        "status": enc_status,
        "evidence": enc_evidence
    })

    checks.append(check_root_mfa(session))
    checks.append(check_cloudtrail(session, regions))
    checks.append(check_ssh_rdp(session, regions))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "instances": instances,
        "buckets": buckets,
        "cis_results": checks
    }


def save_scan(scan):
    if not DYNAMODB_TABLE:
        return False

    dynamodb = _session().resource("dynamodb")
    table = dynamodb.Table(DYNAMODB_TABLE)

    item = {
        "scan_id": scan["generated_at"],
        "generated_at": scan["generated_at"],
        "instances": scan["instances"],
        "buckets": scan["buckets"],
        "cis_results": scan["cis_results"]
    }

    table.put_item(Item=item)

    return True
