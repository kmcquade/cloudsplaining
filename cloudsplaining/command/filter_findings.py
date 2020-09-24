"""
Filters through the results data file to remove exclusions and outputs another data file with the findings only
"""
# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
import logging
import os
from pathlib import Path
import json
import yaml
import click
import click_log
from schema import Optional, Schema, SchemaError
from cloudsplaining.shared.constants import EXCLUSIONS_FILE
from cloudsplaining.shared.exclusions import Exclusions, DEFAULT_EXCLUSIONS
from cloudsplaining.shared.validation import check

logger = logging.getLogger(__name__)
click_log.basic_config(logger)


@click.command(
    short_help="Filters through the results data file to remove exclusions and outputs another data file with the findings only"
)
@click.option(
    "--input-file",
    type=click.Path(exists=True),
    required=True,
    help="Path of the results data file",
)
@click.option(
    "--exclusions-file",
    help="A yaml file containing a list of policy names etc. to exclude from the scan.",
    type=click.Path(exists=True),
    required=False,
    default=EXCLUSIONS_FILE,
)
@click.option(
    "--output",
    required=False,
    type=click.Path(exists=True),
    default=os.getcwd(),
    help="Output directory.",
)
@click_log.simple_verbosity_option()
# pylint: disable=redefined-builtin
def filter_findings(
    input_file, exclusions_file, output
):  # pragma: no cover
    """
    Filters through the results data file to remove exclusions and outputs another data file with the findings only
    """
    if exclusions_file:
        # Get the exclusions configuration
        with open(exclusions_file, "r") as yaml_file:
            try:
                exclusions_cfg = yaml.safe_load(yaml_file)
            except yaml.YAMLError as exc:
                logger.critical(exc)
        exclusions = Exclusions(exclusions_cfg)
    else:
        exclusions = DEFAULT_EXCLUSIONS

    # if os.path.isfile(input_file):
    account_name = Path(input_file).stem
    with open(input_file) as f:
        contents = f.read()
        scan_results = json.loads(contents)
        # Validate scan results format
    check_scan_results_schema(scan_results)
    print("Scan results successful")

    output_directory = output

    findings = []
    finding_types = {
        "aws_managed_policies": "AWS",
        "inline_policies": "Inline",
        "customer_managed_policies": "Customer"
    }
    for finding_type in finding_types:
        for policy_id in scan_results.get(finding_type):
            this_result = scan_results[finding_type][policy_id]
            if not this_result.get("is_excluded"):
                entry = dict(
                    PolicyName=this_result.get("PolicyName"),
                    PolicyId=policy_id,
                    ManagedBy=finding_types[finding_type],
                    PrivilegeEscalation=len(this_result.get("PrivilegeEscalation")),
                    InfrastructureModification=len(this_result.get("InfrastructureModification")),
                    ResourceExposure=len(this_result.get("ResourceExposure")),
                    DataExfiltration=len(this_result.get("DataExfiltration")),
                    ServicesAffected=len(get_services_affected(
                        infrastructure_modification_results=this_result.get("InfrastructureModification"),
                        data_exfiltration_results=this_result.get("DataExfiltration")
                    ))
                )

                findings.append(entry.copy())
            # print(policy_id)
    # print(json.dumps(scan_results, indent=4))
    # print()
    write_findings(findings, account_name, output_directory)


def get_services_affected(infrastructure_modification_results, data_exfiltration_results):
    """Return a list of AWS service prefixes affected by the policy in question."""
    services_affected = []
    for action in infrastructure_modification_results:
        service = action.split(":")[0]
        if service not in services_affected:
            services_affected.append(service)
    # Credentials exposure; since some of those are read-only,
    # they are not in the modify actions so we need to include them here
    # for action in self.credentials_exposure:
    #     service = action.split(":")[0]
    #     if service not in services_affected:
    #         services_affected.append(service)
    # Data Exfiltration; since some of those are read-only,
    # they are not in the modify actions so we need to include them here
    for action in data_exfiltration_results:
        service = action.split(":")[0]
        if service not in services_affected:
            services_affected.append(service)
    services_affected = list(dict.fromkeys(services_affected))
    services_affected.sort()
    return services_affected


def write_findings(results, account_name, output_directory):
    if output_directory is None:
        output_directory = os.getcwd()

    results_data_file = os.path.join(output_directory, f"iam-findings-{account_name}.json")
    if os.path.exists(results_data_file):
        os.remove(results_data_file)
    with open(results_data_file, "w") as file:
        json.dump(results, file, indent=4)

    print(f"Results data saved: {str(results_data_file)}")


SCAN_RESULTS_SCHEMA = Schema(
    {
        "groups": object,
        "users": object,
        "roles": object,
        "aws_managed_policies": object,
        "customer_managed_policies": object,
        "inline_policies": object,
        "exclusions": object,
    }
)


def check_scan_results_schema(cfg):
    """Determine whether or not the scan results schema file meets the required format"""
    result = check(SCAN_RESULTS_SCHEMA, cfg)
    if result:
        return result
    else:
        raise Exception(
            "The required format of the scan results schema is incorrect. Please try again."
        )
