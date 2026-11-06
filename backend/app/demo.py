from datetime import datetime, timezone

def demo_data():
    now = datetime.now(timezone.utc).isoformat()
    instances = [
        {"instance_id":"i-demo1234567890abc","instance_type":"t3.micro","region":"us-east-1","public_ip":"203.0.113.10","security_groups":["sg-demo-web"]},
        {"instance_id":"i-demo0987654321xyz","instance_type":"t2.micro","region":"us-east-1","public_ip":None,"security_groups":["sg-demo-private"]},
    ]
    buckets = [
        {"bucket_name":"demo-private-assets","region":"us-east-1","encrypted":True,"public":False,"public_evidence":"Public access block enabled; no public policy/ACL detected"},
        {"bucket_name":"demo-legacy-uploads","region":"us-west-2","encrypted":False,"public":True,"public_evidence":"Demo finding: public access simulated"},
    ]
    checks = [
        {"check_id":"S3_PUBLIC","title":"S3 buckets are not publicly accessible","status":"FAIL","evidence":"demo-legacy-uploads is simulated as public"},
        {"check_id":"S3_ENCRYPTION","title":"All S3 buckets are encrypted","status":"FAIL","evidence":"demo-legacy-uploads is simulated without default encryption"},
        {"check_id":"ROOT_MFA","title":"Root account MFA is enabled","status":"PASS","evidence":"Demo credential report indicates root MFA enabled"},
        {"check_id":"CLOUDTRAIL","title":"CloudTrail is enabled","status":"PASS","evidence":"Demo trail is multi-region and logging"},
        {"check_id":"SSH_RDP","title":"Security groups do not expose SSH/RDP to 0.0.0.0/0","status":"FAIL","evidence":"sg-demo-web simulated with SSH open to the internet"},
    ]
    return {"generated_at":now,"instances":instances,"buckets":buckets,"cis_results":checks}
