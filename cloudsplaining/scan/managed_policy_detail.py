"""Represents the Policies section of the output generated by the aws iam get-account-authorization-details command."""
# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
import logging
from policy_sentry.util.arns import get_account_from_arn
from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.shared.utils import get_full_policy_path
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS, Exclusions, is_name_excluded

logger = logging.getLogger(__name__)


class ManagedPolicyDetails:
    """
    Holds ManagedPolicy objects. This is sourced from the 'Policies' section of the Authz file - whether they are AWS managed or customer managed.
    """

    def __init__(self, policy_details, exclusions=DEFAULT_EXCLUSIONS):
        self.policy_details = []
        if not isinstance(exclusions, Exclusions):
            raise Exception(
                "The exclusions provided is not an Exclusions type object. "
                "Please supply an Exclusions object and try again."
            )
        self.exclusions = exclusions

        for policy_detail in policy_details:
            this_policy_name = policy_detail.get("PolicyName")
            this_policy_id = policy_detail.get("PolicyId")
            this_policy_path = policy_detail.get("Path")
            # Always exclude the AWS service role policies
            if (
                is_name_excluded(this_policy_path, "aws-service-role*")
                or is_name_excluded(this_policy_path, "/aws-service-role*")
            ):
                logger.debug("The %s Policy with the policy ID %s is excluded because it is "
                             "an immutable AWS Service role with a path of %s",
                             this_policy_name, this_policy_id, this_policy_path)
                continue
            # Exclude the managed policies
            if (
                exclusions.is_policy_excluded(this_policy_name)
                or exclusions.is_policy_excluded(this_policy_id)
                or exclusions.is_policy_excluded(this_policy_path)
            ):
                logger.debug("The %s Managed Policy with the policy ID %s and %s path is excluded.",
                             this_policy_name, this_policy_id, this_policy_path)
                continue
            self.policy_details.append(ManagedPolicy(policy_detail, exclusions))

    def get_policy_detail(self, arn):
        """Get a ManagedPolicy object by providing the ARN. This is useful to PrincipalDetail objects"""
        result = None
        for policy_detail in self.policy_details:
            if policy_detail.arn == arn:
                result = policy_detail
                break
        if not result:
            raise Exception("Managed Policy ARN %s not found.", arn)
        return result

    @property
    def json(self):
        """Get all JSON results"""
        result = {}
        for policy in self.policy_details:
            result[policy.policy_id] = policy.json
        return result

    @property
    def json_large(self):
        """Get all JSON results"""
        result = {}
        for policy in self.policy_details:
            result[policy.policy_id] = policy.json_large
        return result

    @property
    def json_large_aws_managed(self):
        """Get all JSON results"""
        result = {}
        for policy in self.policy_details:
            if policy.managed_by == "AWS":
                result[policy.policy_id] = policy.json_large
        return result

    @property
    def json_large_customer_managed(self):
        """Get all JSON results"""
        result = {}
        for policy in self.policy_details:
            if policy.managed_by == "Customer":
                result[policy.policy_id] = policy.json_large
        return result


# pylint: disable=too-many-instance-attributes
class ManagedPolicy:
    """
    Contains information about an IAM Managed Policy, including the Policy Document.

    https://docs.aws.amazon.com/IAM/latest/APIReference/API_PolicyDetail.html
    """

    def __init__(self, policy_detail, exclusions=DEFAULT_EXCLUSIONS):
        # Store the Raw JSON data from this for safekeeping
        self.policy_detail = policy_detail

        # Store the attributes per Policy item
        self.policy_name = policy_detail.get("PolicyName")
        self.policy_id = policy_detail.get("PolicyId")
        self.arn = policy_detail.get("Arn")
        self.path = policy_detail.get("Path")
        self.default_version_id = policy_detail.get("DefaultVersionId")
        self.attachment_count = policy_detail.get("AttachmentCount")
        self.permissions_boundary_usage_count = policy_detail.get(
            "PermissionsBoundaryUsageCount"
        )
        self.is_attachable = policy_detail.get("IsAttachable")
        self.create_date = policy_detail.get("CreateDate")
        self.update_date = policy_detail.get("UpdateDate")

        if not isinstance(exclusions, Exclusions):
            raise Exception(
                "The exclusions provided is not an Exclusions type object. "
                "Please supply an Exclusions object and try again."
            )
        self.exclusions = exclusions
        self.is_excluded = self._is_excluded(exclusions)

        # Policy Documents are stored here. Multiple indices though. We will evaluate the one
        #   with IsDefaultVersion only.
        self.policy_version_list = policy_detail.get("PolicyVersionList")

        self.policy_document = self._policy_document()

    def _is_excluded(self, exclusions):
        """Determine whether the policy name or policy ID is excluded"""
        return bool(
            exclusions.is_policy_excluded(self.policy_name)
            or exclusions.is_policy_excluded(self.policy_id)
            or exclusions.is_policy_excluded(self.path)
            or is_name_excluded(self.path, "/aws-service-role*")
        )

    def _policy_document(self):
        """Return the policy document object"""
        policy_document = {}
        for policy_version in self.policy_version_list:
            if policy_version.get("IsDefaultVersion") is True:
                policy_document = PolicyDocument(policy_version.get("Document"), exclusions=self.exclusions)
        return policy_document

    # This will help with the Exclusions mechanism. Get the full path of the policy, including the name.
    @property
    def full_policy_path(self):
        """Get the full policy path, including /aws-service-role/, if applicable"""
        return get_full_policy_path(self.arn)

    @property
    def managed_by(self):  # pragma: no cover
        """Determine whether the policy is AWS-Managed or Customer-managed based on a Policy ARN pattern."""
        if "arn:aws:iam::aws:" in self.arn:
            return "AWS"
        else:
            return "Customer"

    @property
    def account_id(self):  # pragma: no cover
        """Return the account ID"""
        if "arn:aws:iam::aws:" in self.arn:
            return "N/A"
        else:
            account_id = get_account_from_arn(self.arn)
            return account_id

    @property
    def json(self):
        """Return JSON output for high risk actions"""
        result = dict(
            PolicyName=self.policy_name,
            PolicyId=self.policy_id,
            Arn=self.arn,
            Path=self.path,
            DefaultVersionId=self.default_version_id,
            AttachmentCount=self.attachment_count,
            IsAttachable=self.is_attachable,
            CreateDate=self.create_date,
            UpdateDate=self.update_date,
            PolicyVersionList=self.policy_version_list,
            PrivilegeEscalation=self.policy_document.allows_privilege_escalation,
            DataExfiltration=self.policy_document.allows_data_exfiltration_actions,
            ResourceExposure=self.policy_document.permissions_management_without_constraints,
            ServiceWildcard=self.policy_document.service_wildcard,
            CredentialsExposure=self.policy_document.credentials_exposure,
            is_excluded=self.is_excluded
        )
        return result

    @property
    def json_large(self):
        """Return JSON output - including Infra Modification actions, which can be large"""
        result = dict(
            PolicyName=self.policy_name,
            PolicyId=self.policy_id,
            Arn=self.arn,
            Path=self.path,
            DefaultVersionId=self.default_version_id,
            AttachmentCount=self.attachment_count,
            IsAttachable=self.is_attachable,
            CreateDate=self.create_date,
            UpdateDate=self.update_date,
            PolicyVersionList=self.policy_version_list,
            PrivilegeEscalation=self.policy_document.allows_privilege_escalation,
            DataExfiltration=self.policy_document.allows_data_exfiltration_actions,
            ResourceExposure=self.policy_document.permissions_management_without_constraints,
            ServiceWildcard=self.policy_document.service_wildcard,
            CredentialsExposure=self.policy_document.credentials_exposure,
            InfrastructureModification=self.policy_document.infrastructure_modification,
            is_excluded=self.is_excluded,
            # InfrastructureModification=self.policy_document.all_allowed_unrestricted_actions
        )
        return result
