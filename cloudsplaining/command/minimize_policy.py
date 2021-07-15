"""
Minimizes the character count of an IAM Policy file. Example: s3:GetObject and s3:GetObjectAcl become s3:GetObjec*, etc.
"""
import logging
import json
import click
from policy_sentry.analysis.expand import get_expanded_policy
from cloudsplaining import set_log_level

logger = logging.getLogger(__name__)


@click.command(
    short_help="Expand the * Actions in IAM policy files to improve readability"
)
@click.option("--input-file", "-i", type=click.Path(exists=True), required=True, help="Path to the JSON policy file.")
@click.option("-v", "--verbose", "verbosity", help="Log verbosity level.", count=True)
def minimize_policy(input_file: str, verbosity: int) -> None:
    set_log_level(verbosity)
    with open(input_file) as json_file:
        logger.debug(f"Opening {input_file}")
        data = json.load(json_file)
        policy = get_expanded_policy(data)
        print(json.dumps(policy, indent=4))


def minimize(policy_document: dict):
    print()
