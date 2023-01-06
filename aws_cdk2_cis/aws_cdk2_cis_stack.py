from aws_cdk import (
    CustomResource,
    RemovalPolicy,
    Duration,
    Stack,
    aws_s3 as s3,
    aws_s3_notifications as s3n,
    aws_cloudtrail as cloudtrail,
    aws_kms as kms,
    aws_logs as logs,
    aws_iam as iam,
    aws_config as config,
    aws_sns as sns,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_cloudwatch as cloudwatch,
    aws_lambda as _lambda,
    custom_resources as cr,
    aws_guardduty as guardduty,
    aws_ecr as ecr,
)
from constructs import Construct
from os import path


class AwsCdk2CisStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        removal = RemovalPolicy.DESTROY
        security_distribution_list_email = 'daniel+awssecurity@severalclouds.com'

        security_notifications_topic = sns.Topic(self, 'CIS_Topic',
                                                 display_name='CIS_Topic',
                                                 topic_name='CIS_Topic',
                                                 )

        sns.Subscription(self, 'CIS_Subscription',
                         topic=security_notifications_topic,
                         protocol=sns.SubscriptionProtocol.EMAIL,
                         endpoint=security_distribution_list_email
                         )

        lifecycle_rule = s3.LifecycleRule(
            abort_incomplete_multipart_upload_after=Duration.days(1),
        )

        # Ensure AWS Config is enabled / Ensure CloudTrail is enabled in all Regions 2.1 - 2.8
        cloudtrail_bucket_accesslogs = s3.Bucket(self, "CloudTrailS3Accesslogs",
                                                 block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                                 encryption=s3.BucketEncryption.S3_MANAGED,
                                                 removal_policy=removal,
                                                 enforce_ssl=True,
                                                 lifecycle_rules=[
                                                     lifecycle_rule]
                                                 )

        cloudtrail_bucket_accesslogs.add_event_notification(
            s3.EventType.OBJECT_REMOVED,
            s3n.SnsDestination(security_notifications_topic)
        )

        cloudtrail_bucket = s3.Bucket(self, "CloudTrailS3",
                                      block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                      encryption=s3.BucketEncryption.S3_MANAGED,
                                      removal_policy=removal,
                                      server_access_logs_bucket=cloudtrail_bucket_accesslogs,
                                      enforce_ssl=True,
                                      lifecycle_rules=[
                                          lifecycle_rule],
                                      #   intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(
                                      #       name="CloudTrailS3IntelligentTiering"
                                      #   )]
                                      )

        cloudtrail_bucket.add_event_notification(
            s3.EventType.OBJECT_REMOVED,
            s3n.SnsDestination(security_notifications_topic)
        )

        cloudtrail_kms = kms.Key(self, "CloudTrailKey",
                                 enable_key_rotation=True,
                                 removal_policy=removal
                                 )

        cloudtrail_kms.grant(iam.ServicePrincipal(
            'cloudtrail.amazonaws.com'), 'kms:DescribeKey')

        cloudtrail_kms.grant(iam.ServicePrincipal(
            'cloudtrail.amazonaws.com', conditions={
                'StringLike': {'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*:'+Stack.of(self).account+':trail/*'}
            }), 'kms:GenerateDataKey*')

        cloudtrail_kms.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:ReEncryptFrom"],
            conditions={
                'StringEquals': {'kms:CallerAccount': Stack.of(self).account},
                'StringLike': {'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*:'+Stack.of(self).account+':trail/*'}
            },
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            resources=['*']
        ))

        cloudtrail_kms.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:CreateAlias"],
            conditions={
                'StringEquals': {'kms:CallerAccount': Stack.of(self).account,
                                 'kms:ViaService': 'ec2.' +
                                 Stack.of(self).region+'.amazonaws.com'}
            },
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            resources=['*']
        ))

        cloudtrail_kms.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:ReEncryptFrom"],
            conditions={
                'StringEquals': {'kms:CallerAccount': Stack.of(self).account},
                'StringLike': {'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*:'+Stack.of(self).account+':trail/*'}
            },
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            resources=['*']
        ))

        # CloudTrail - single account, not Organization
        trail = cloudtrail.Trail(self, "CloudTrail",
                                 enable_file_validation=True,
                                 is_multi_region_trail=True,
                                 include_global_service_events=True,
                                 send_to_cloud_watch_logs=True,
                                 cloud_watch_logs_retention=logs.RetentionDays.FOUR_MONTHS,
                                 bucket=cloudtrail_bucket,
                                 encryption_key=cloudtrail_kms
                                 )

        config_role = iam.CfnServiceLinkedRole(self,
                                               id='ServiceLinkedRoleConfig',
                                               aws_service_name='config.amazonaws.com'
                                               )

        # global_config = config.CfnConfigurationRecorder(self, 'ConfigRecorder',
        #                                                 name='default',
        #                                                 role_arn="arn:aws:iam::"+Stack.of(self).account+":role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        #                                                 recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
        #                                                     all_supported=True,
        #                                                     include_global_resource_types=True
        #                                                 )
        #                                                 )

        cloudwatch_actions_cis = cloudwatch_actions.SnsAction(
            security_notifications_topic)

        cis_metricfilter_alarms = {
            'CIS-3.1-UnauthorizedAPICalls': '($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")',
            'CIS-3.2-ConsoleSigninWithoutMFA': '($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")',
            'RootAccountUsageAlarm': '$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"',
            'CIS-3.4-IAMPolicyChanges': '($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)',
            'CIS-3.5-CloudTrailChanges': '($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)',
            'CIS-3.6-ConsoleAuthenticationFailure': '($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")',
            'CIS-3.7-DisableOrDeleteCMK': '($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))',
            'CIS-3.8-S3BucketPolicyChanges': '($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))',
            'CIS-3.9-AWSConfigChanges': '($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))',
            'CIS-3.10-SecurityGroupChanges': '($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)',
            'CIS-3.11-NetworkACLChanges': '($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)',
            'CIS-3.12-NetworkGatewayChanges': '($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)',
            'CIS-3.13-RouteTableChanges': '($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)',
            'CIS-3.14-VPCChanges': '($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)',
        }
        for x, y in cis_metricfilter_alarms.items():
            str_x = str(x)
            str_y = str(y)
            logs.MetricFilter(self, "MetricFilter_"+str_x,
                              log_group=trail.log_group,
                              filter_pattern=logs.JsonPattern(
                                  json_pattern_string=str_y),
                              metric_name=str_x,
                              metric_namespace="LogMetrics",
                              metric_value='1'
                              )
            cloudwatch.Alarm(self, "Alarm_"+str_x,
                             alarm_name=str_x,
                             alarm_description=str_x,
                             comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                             evaluation_periods=1,
                             threshold=1,
                             metric=cloudwatch.Metric(metric_name=str_x,
                                                      namespace="LogMetrics"
                                                      ),
                             ).add_alarm_action(cloudwatch_actions_cis)

        # TODO KMS key for the SNS topic

        support_role = iam.Role(self, "SupportRole",
                                assumed_by=iam.AccountPrincipal(
                                    account_id=Stack.of(self).account),
                                managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                                    'AWSSupportAccess')],
                                role_name='AWSSupportAccess',
                                )

        account_password_policy_parameters = {
            "AllowUsersToChangePassword": True,
            "HardExpiry": False,
            "MaxPasswordAge": 90,
            "MinimumPasswordLength": 14,
            "PasswordReusePrevention": 24,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "RequireUppercaseCharacters": True,
        }

        passwordPolicy = cr.AwsCustomResource(self, "PasswordPolicy",
                                              on_create=cr.AwsSdkCall(
                                                  service="IAM",
                                                  action="updateAccountPasswordPolicy",
                                                  parameters=account_password_policy_parameters,
                                                  physical_resource_id=cr.PhysicalResourceId.of(
                                                      "AccountPasswordPolicy"),
                                              ),
                                              on_update=cr.AwsSdkCall(
                                                  service="IAM",
                                                  action="updateAccountPasswordPolicy",
                                                  parameters=account_password_policy_parameters,
                                                  physical_resource_id=cr.PhysicalResourceId.of(
                                                      "AccountPasswordPolicy"),
                                              ),
                                              on_delete=cr.AwsSdkCall(
                                                  service="IAM",
                                                  action="deleteAccountPasswordPolicy",
                                              ),
                                              policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                                                  resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
                                              )
                                              )

        default_ebs_encryption = cr.AwsCustomResource(self, "DefaultEbsEncryption",
                                                      on_create=cr.AwsSdkCall(
                                                            service="EC2",
                                                            action="enableEbsEncryptionByDefault",
                                                            physical_resource_id=cr.PhysicalResourceId.of(
                                                                "EbsEncryptionByDefault"),
                                                      ),
                                                      on_update=cr.AwsSdkCall(
                                                          service="EC2",
                                                          action="enableEbsEncryptionByDefault",
                                                          physical_resource_id=cr.PhysicalResourceId.of(
                                                              "EbsEncryptionByDefault"),
                                                      ),
                                                      on_delete=cr.AwsSdkCall(
                                                          service="EC2",
                                                          action="disableEbsEncryptionByDefault",
                                                      ),
                                                      policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                                                          resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
                                                      )
                                                      )

        put_public_access_block = cr.AwsCustomResource(self, "putPublicAccessBlock",
                                                       on_create=cr.AwsSdkCall(
                                                           service="S3Control",
                                                           action="putPublicAccessBlock",
                                                           physical_resource_id=cr.PhysicalResourceId.of(
                                                               "putPublicAccessBlockid"),
                                                           parameters={
                                                               "AccountId": Stack.of(self).account,
                                                               "PublicAccessBlockConfiguration": {
                                                                   "BlockPublicAcls": True,
                                                                   "BlockPublicPolicy": True,
                                                                   "IgnorePublicAcls": True,
                                                                   "RestrictPublicBuckets": True,
                                                               }
                                                           }
                                                       ),
                                                       #   on_update=cr.AwsSdkCall(
                                                       #   on_delete=cr.AwsSdkCall(
                                                       policy=cr.AwsCustomResourcePolicy.from_statements(
                                                           [iam.PolicyStatement(
                                                               actions=[
                                                                   "s3control:PutPublicAccessBlock", "s3:PutAccountPublicAccessBlock"],
                                                               effect=iam.Effect.ALLOW,
                                                               resources=['*']
                                                           )]
                                                       )
                                                       )

        guardduty_detector = guardduty.CfnDetector(self, 'GuardDutyDetector',
                                                   enable=True
                                                   )
