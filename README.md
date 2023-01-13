
# Welcome AWS SecurityHub CIS mitigation

## checklist

[] Modify the cdk bootstrap CF, to achieve compliance [S3.13]

```
cdk bootstrap --show-template > bootstrap-template.yaml
```

```
      LifecycleConfiguration:
        Rules:
          - AbortIncompleteMultipartUpload:
              DaysAfterInitiation: 1
            Status: Enabled
```

```
aws cloudformation update-stack --stack-name CDKToolkit --template-body file://bootstrap-template.yaml --capabilities CAPABILITY_NAMED_IAM
aws cloudformation create-change-set --stack-name CDKToolkit --template-body file://bootstrap-template.yaml --change-set-name CDKToolkit1 --capabilities CAPABILITY_NAMED_IAM
```

[] ECR repositories should have at least one lifecycle policy configured [ECR.3]

```
      LifecyclePolicy:
        LifecyclePolicyText: '{"rules":[{"rulePriority":1,"selection":{"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":10000},"action":{"type":"expire"}}]}'
```

```
cdk bootstrap --show-template > bootstrap-template.yaml
aws cloudformation update-stack --stack-name CDKToolkit --template-body file://bootstrap-template.yaml --capabilities CAPABILITY_NAMED_IAM
aws cloudformation create-change-set --stack-name CDKToolkit --template-body file://bootstrap-template.yaml --change-set-name CDKToolkit1 --capabilities CAPABILITY_NAMED_IAM
```
