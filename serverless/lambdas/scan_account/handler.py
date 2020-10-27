#!/usr/bin/env python3
import os
import sys
import logging
import json
import boto3
import webbrowser
from cloudsplaining.shared.validation import check_authorization_details_schema
from cloudsplaining.shared.exclusions import Exclusions
from cloudsplaining.shared.constants import DEFAULT_EXCLUSIONS_CONFIG
from cloudsplaining.scan.authorization_details import AuthorizationDetails
from cloudsplaining.output.report import HTMLReport
from policy_sentry.util.arns import get_account_from_arn
from botocore.exceptions import ClientError

SAVE_BUCKET = os.environ['SAVE_BUCKET']
TARGET_ROLE_NAME = os.environ['TARGET_ROLE_NAME']
TRUSTED_ROLE_NAME = os.environ['TRUSTED_ROLE_NAME']

# Get the current account ID
sts = boto3.client("sts")
user_arn = sts.get_caller_identity()["Arn"]
THIS_ACCOUNT_ID = user_arn.split(":")[4]
# Get the jump credentials
jump_creds = sts.assume_role(RoleArn=f"arn:aws:iam::{THIS_ACCOUNT_ID}:role/{TRUSTED_ROLE_NAME}", RoleSessionName="iamScan")['Credentials']

# Logging stuff
logger = logging.getLogger(__name__)
root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

# Boto3 S3 stuff
s3 = boto3.resource('s3')
s3_client = boto3.client("s3")


def run_cloudsplaining_scan(account_authorization_details_cfg, exclusions):
    check_authorization_details_schema(account_authorization_details_cfg)
    authorization_details = AuthorizationDetails(account_authorization_details_cfg, exclusions)
    results = authorization_details.results
    return results


def write_html_report(results, account_alias, minimize):
    # Lazy method to get an account ID
    account_id = None
    for role in results.get("roles"):
        if "arn:aws:iam::aws:" not in results["roles"][role]["arn"]:
            account_id = get_account_from_arn(results["roles"][role]["arn"])
            break

    html_report = HTMLReport(
        account_id=account_id,
        account_name=account_alias,
        results=results,
        minimize=minimize
    )
    rendered_report = html_report.get_html_report()
    return rendered_report


def write_object_to_s3(content, bucket, key):
    """Write an object to S3"""
    try:
        print("Writing the object")
        response = s3_client.put_object(
            ACL="private",
            Bucket=bucket,
            Key=key,
            ServerSideEncryption="AES256",
            Body=content
        )
        print(response)
    except:
        print("I tried so hard and got so far")
        print("But in the end it doesn't even matter")


def open_report_locally(rendered_html_report):
    html_output_file = os.path.join(os.getcwd(), f"iam-report-local.html")
    logger.info("Saving the report to %s", html_output_file)
    if os.path.exists(html_output_file):
        os.remove(html_output_file)

    with open(html_output_file, "w") as f:
        f.write(rendered_html_report)
    print(f"Wrote HTML results to: {html_output_file}")

    # Open the report by default
    print("Opening the HTML report")
    url = "file://%s" % os.path.abspath(html_output_file)
    webbrowser.open(url, new=2)


# def validate_exclusions_schema_from_s3(bucket, key="exclusions.yml"):
#     exclusions_yml = get_object_from_s3(bucket, key)
#     try:
#         exclusions_cfg = yaml.safe_load(exclusions_yml)
#     except yaml.YAMLError as exc:
#         logger.critical(exc)
#         sys.exit()
#     exclusions = Exclusions(exclusions_cfg)
#     logger.info("Exclusions config: " + str(exclusions_cfg))
#     return exclusions

def iam_scan_authorization_details(target_account_id, target_account_role_name):
    results = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }
    session = boto3.session.Session()
    sts = session.client('sts', aws_access_key_id=jump_creds['AccessKeyId'],
                         aws_secret_access_key=jump_creds['SecretAccessKey'],
                         aws_session_token=jump_creds['SessionToken'])
    arn = f"arn:aws:iam::{target_account_id}:role/{target_account_role_name}"
    try:
        role = sts.assume_role(RoleArn=arn, RoleSessionName="iamScanning")
        creds = role['Credentials']
        sts_session = boto3.session.Session(aws_access_key_id=creds['AccessKeyId'],
                                            aws_secret_access_key=creds['SecretAccessKey'],
                                            aws_session_token=creds['SessionToken'])
    except ClientError as e:
        print(arn + e.response['Error']['Message'])
        return 0
    iam = sts_session.client('iam')
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User"]):
        # Always add inline user policies
        results["UserDetailList"].extend(page["UserDetailList"])
    for page in paginator.paginate(Filter=["Group"]):
        results["GroupDetailList"].extend(page["GroupDetailList"])
    for page in paginator.paginate(Filter=["Role"]):
        results["RoleDetailList"].extend(page["RoleDetailList"])
        # Ignore Service Linked Roles
        for policy in page["Policies"]:
            if policy["Path"] != "/service-role/":
                results["RoleDetailList"].append(policy)
    for page in paginator.paginate(Filter=["LocalManagedPolicy"]):
        # Add customer-managed policies IF they are attached to IAM principals
        for policy in page["Policies"]:
            if policy["AttachmentCount"] > 0:
                results["Policies"].append(policy)
    for page in paginator.paginate(Filter=["AWSManagedPolicy"]):
        # Add customer-managed policies IF they are attached to IAM principals
        for policy in page["Policies"]:
            if policy["AttachmentCount"] > 0:
                results["Policies"].append(policy)
    return results


def run_end_to_end_scan(account_alias, account_authorization_details_cfg, exclusions, output_bucket, s3_output_scan_path, minimize):
    json_data_output_key_path = f"{s3_output_scan_path}/data/{account_alias}.json"
    html_output_key_path = f"{s3_output_scan_path}/html/{account_alias}.html"

    # Run the scan,  get the big dictionary of results, and write that data file to S3
    results = run_cloudsplaining_scan(json.loads(account_authorization_details_cfg), exclusions)
    print("Scan complete! Writing data file to S3")
    write_object_to_s3(json.dumps(results), output_bucket, json_data_output_key_path)

    print("Getting the rendered HTML report")
    # # Create the HTML report so we can store it in S3
    rendered_html_report = write_html_report(results, account_alias, minimize)

    print("HTML Report done! Writing it to S3")
    write_object_to_s3(rendered_html_report, output_bucket, html_output_key_path)
    return html_output_key_path, json_data_output_key_path


def get_details_from_sns_event(event):
    target_account_id = None
    target_account_alias = None
    bucket_output_prefix = None
    if event.get("Records")[0].get("Sns"):
        message = event.get('Records')[0].get('Sns').get('Message')
        default_message = json.loads(message)
        print(default_message)
        if not (
            default_message.get("target_account_id")
            and default_message.get("target_account_alias")
            and default_message.get("bucket_output_prefix")
        ):
            raise Exception("The SNS message does not contain the expected fields. Please try again")
        else:
            target_account_id = default_message.get("target_account_id")
            target_account_alias = default_message.get("target_account_alias")
            bucket_output_prefix = default_message.get("bucket_output_prefix")
    return target_account_id, target_account_alias, bucket_output_prefix


def handler(event, context):
    target_account_id, target_account_alias, bucket_output_prefix = get_details_from_sns_event(event)
    s3_output_scan_path = f"{bucket_output_prefix}/{target_account_id}"

    # TODO: Optionally accept the exclusions through SNS
    exclusions = Exclusions(DEFAULT_EXCLUSIONS_CONFIG)
    logger.info("Exclusions config: " + str(DEFAULT_EXCLUSIONS_CONFIG))

    account_authorization_details_cfg = iam_scan_authorization_details(target_account_id, TARGET_ROLE_NAME)
    html_result_path, json_results_path = run_end_to_end_scan(
        account_alias=target_account_alias,
        account_authorization_details_cfg=account_authorization_details_cfg,
        exclusions=exclusions,
        output_bucket=SAVE_BUCKET,
        s3_output_scan_path=s3_output_scan_path,
        minimize=True
    )
    # Return a good status code to show we are done
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Scan complete",
            "html_results": f"s3://{SAVE_BUCKET}/{html_result_path}",
            "json_results": f"s3://{SAVE_BUCKET}/{json_results_path}"
        }),
    }


if __name__ == '__main__':
    this_account_alias = "test"
    this_bucket_output_prefix = ""
    this_event = {
        "target_account_id": THIS_ACCOUNT_ID,
        "target_account_alias": this_account_alias,
        "bucket_output_prefix": this_bucket_output_prefix,
    }
    handler(this_event, "test")
