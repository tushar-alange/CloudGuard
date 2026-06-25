import json
import datetime
import os
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    print("CloudGuard Core Scanner Initialized...")
    
    # Grab the SNS Topic address injected from our template.yaml
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    
    # This list will hold any security issues we find
    security_findings = []

    # ==========================================
    # 1. S3 BUCKET SCANNER
    # ==========================================
    s3_client = boto3.client('s3')
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                public_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_block['PublicAccessBlockConfiguration']
                if config.get('BlockPublicAccess') != True:
                    security_findings.append(f"🚨 S3 WARNING: Bucket [{bucket_name}] does not have full public access blocks enabled!")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    security_findings.append(f"🚨 S3 CRITICAL: Bucket [{bucket_name}] has NO Public Access Block configuration set!")
    except Exception as e:
        print(f"❌ S3 scan failed: {str(e)}")

    # ==========================================
    # 2. IAM ACCESS KEY AGE SCANNER
    # ==========================================
    iam_client = boto3.client('iam')
    try:
        users_response = iam_client.list_users()
        users = users_response.get('Users', [])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        max_age_days = 90
        
        for user in users:
            username = user['UserName']
            keys_response = iam_client.list_access_keys(UserName=username)
            access_keys = keys_response.get('AccessKeyMetadata', [])
            
            for key in access_keys:
                key_id = key['AccessKeyId']
                age_days = (now - key['CreateDate']).days
                
                if age_days > max_age_days:
                    security_findings.append(f"🚨 IAM WARNING: User [{username}] has an unrotated access key [{key_id}] (Age: {age_days} days).")
    except Exception as e:
        print(f"❌ IAM scan failed: {str(e)}")

    # ==========================================
    # 3. ALERT GENERATION & DELIVERY
    # ==========================================
    if security_findings:
        print(f"Found {len(security_findings)} security issues. Sending alert dispatch...")
        
        # Format the email content beautifully
        email_body = "CloudGuard Security Compliance Digest\n"
        email_body += "=========================================\n\n"
        email_body += "\n".join(security_findings)
        email_body += "\n\n=========================================\n"
        email_body += f"Scan timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        sns_client = boto3.client('sns')
        try:
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject="⚠️ CloudGuard Security Alert Digest",
                Message=email_body
            )
            print("Alert successfully sent to SNS Channel!")
        except Exception as e:
            print(f"❌ Failed to send SNS notification: {str(e)}")
    else:
        print("🟢 Account clean. Zero compliance alerts generated.")

    return {
        "statusCode": 200,
        "body": json.dumps({"message": "CloudGuard safety check completed."}),
    }