import * as cdk from "@aws-cdk/core";
import * as s3 from "@aws-cdk/aws-s3";
import * as lambda from "@aws-cdk/aws-lambda";
import * as iam from "@aws-cdk/aws-iam";
import * as events from "@aws-cdk/aws-events";
import * as targets from "@aws-cdk/aws-events-targets";

type BucketProps = Partial<Omit<s3.BucketProps, "bucketName">>;
type LambdaProps = Partial<lambda.FunctionProps> & {
  environment: {
    BUCKET: string;
    DIRECTORY_URL: string;
    ACCOUNT_EMAIL: string;
  };
  code: lambda.Code;
};

export class CdkLambdaACMEStack extends cdk.Stack {
  fn: lambda.Function;
  bucket: s3.Bucket;
  constructor(
    scope: cdk.Construct,
    id: string,
    lambdaProps: LambdaProps,
    bucketProps: BucketProps = {}
  ) {
    super(scope, id);
    this.fn = this.createLambda(lambdaProps);
    this.bucket = this.createBucket({
      ...bucketProps,
      bucketName: lambdaProps.environment.BUCKET,
    });
    this.bucket.grantReadWrite(this.fn);
  }

  createSchedule(fn: lambda.Function) {
    new events.Rule(this, "LambdaAcmeScheduleRule", {
      schedule: events.Schedule.rate(cdk.Duration.days(3)),
      targets: [
        new targets.LambdaFunction(fn, {
          event: events.RuleTargetInput.fromObject({ action: "renew" }),
        }),
      ],
    });
  }

  createLambda(props: LambdaProps) {
    const fn = new lambda.Function(this, "LambdaAcme", {
      functionName: "lambda-acme",
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "main.handler",
      timeout: cdk.Duration.seconds(300),
      memorySize: 1024,
      ...props,
    });
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["acm:ImportCertificate", "acm:DeleteCertificate"],
        resources: ["arn:aws:acm:*"],
        effect: iam.Effect.ALLOW,
      })
    );
    return fn;
  }

  createBucket(props: s3.BucketProps) {
    const bucket = new s3.Bucket(this, "LambdaAcmeBucket", props);
    bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject"],
        resources: [bucket.arnForObjects(".well-known/acme-challenge/*")],
        effect: iam.Effect.ALLOW,
        principals: [new iam.ArnPrincipal("*")],
      })
    );
    bucket.addLifecycleRule({
      expiration: cdk.Duration.days(1),
      prefix: ".well-known/acme-challenge",
    });
    new cdk.CfnOutput(this, "LambdaAcmeRedirectDomain", {
      value: bucket.bucketRegionalDomainName,
    });
    return bucket;
  }
}
